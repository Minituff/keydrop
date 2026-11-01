package server

import (
	"net/http"
	"net/url"
	"slices"
	"strings"
	"testing"

	"github.com/minituff/keydrop/internal/store"
)

func tokenNamespaces(t *testing.T, st *store.Store, name string) []string {
	t.Helper()
	for _, tk := range st.ListTokens() {
		if tk.Name == name {
			return tk.Namespaces
		}
	}
	t.Fatalf("no token %s", name)
	return nil
}

func TestNamespacePicker(t *testing.T) {
	h := newHarness(t)
	h.setup()
	h.st.PutValue("lab", "A", []byte("x"), nil)
	h.st.PutValue("prod", "B", []byte("x"), nil)
	_, body := h.get("/new")
	for _, want := range []string{`<select name="namespace"`, `<option value="lab"`, `<option value="prod"`, `value="&#43;new"`, `+ New namespace`, `name="new_namespace"`} {
		if !strings.Contains(body, want) {
			t.Fatalf("New page: missing %s", want)
		}
	}
	// An existing namespace: no new-namespace note.
	if code, body := h.form("/secrets", url.Values{"namespace": {"lab"}, "name": {"C"}, "kind": {"secret"}, "value": {"x"}}); code != http.StatusSeeOther || strings.Contains(body, "Saved in a new namespace") {
		t.Fatalf("existing namespace: %d", code)
	}
	// "+ New namespace": created, lower-cased, and the admin is told no
	// agent can read it yet.
	code, body := h.form("/secrets", url.Values{"namespace": {"+new"}, "new_namespace": {"Media"}, "name": {"D"}, "kind": {"secret"}, "value": {"x"}})
	if code != http.StatusSeeOther || !strings.Contains(body, "Saved in a new namespace") {
		t.Fatalf("new namespace: %d", code)
	}
	if _, ok := h.st.GetSecret("media", "D"); !ok {
		t.Fatal("media/D not saved")
	}
	// Picking "+ New" with an existing name is just that namespace.
	if code, body := h.form("/secrets", url.Values{"namespace": {"+new"}, "new_namespace": {"lab"}, "name": {"E"}, "kind": {"secret"}, "value": {"x"}}); code != http.StatusSeeOther || strings.Contains(body, "Saved in a new namespace") {
		t.Fatalf("new = existing: %d", code)
	}
	// "+ New" with nothing typed, or a bad name, is refused.
	for _, nn := range []string{"", "-bad", "a b"} {
		if code, _ := h.form("/secrets", url.Values{"namespace": {"+new"}, "new_namespace": {nn}, "name": {"F"}, "kind": {"secret"}, "value": {"x"}}); code != http.StatusBadRequest {
			t.Fatalf("new namespace %q: %d", nn, code)
		}
	}
	if slices.Contains(h.st.Namespaces(), "+new") {
		t.Fatal("+new became a namespace")
	}
}

func TestTokenNamespacesForm(t *testing.T) {
	h := newHarness(t)
	h.setup()
	h.st.PutValue("lab", "A", []byte("x"), nil)
	h.st.PutValue("prod", "B", []byte("x"), nil)
	// Creating a token: ticked namespaces plus typed new ones.
	if code, _ := h.form("/tokens", url.Values{"name": {"box"}, "ns": {"lab"}, "namespaces": {"Media, lab"}, "permission": {"read"}}); code != 200 && code != http.StatusSeeOther {
		t.Fatalf("create: %d", code)
	}
	if got := tokenNamespaces(t, h.st, "box"); !slices.Equal(got, []string{"lab", "media"}) {
		t.Fatalf("created with %v", got)
	}
	_, body := h.get("/tokens")
	if !strings.Contains(body, `action="/tokens/box/namespaces"`) {
		t.Fatal("Agents page: no namespaces form")
	}
	// Editing: replaces the list.
	if code, body := h.form("/tokens/box/namespaces", url.Values{"ns": {"prod"}}); code != http.StatusSeeOther || !strings.Contains(body, "Namespaces saved") {
		t.Fatalf("edit: %d", code)
	}
	if got := tokenNamespaces(t, h.st, "box"); !slices.Equal(got, []string{"prod"}) {
		t.Fatalf("edited to %v", got)
	}
	// Nothing ticked, a bad name, or an unknown agent: refused, unchanged.
	for _, f := range []url.Values{{}, {"namespaces": {"-bad"}}} {
		if code, _ := h.form("/tokens/box/namespaces", f); code != http.StatusBadRequest {
			t.Fatalf("bad edit %v: %d", f, code)
		}
	}
	if code, _ := h.form("/tokens/nobody/namespaces", url.Values{"ns": {"lab"}}); code != http.StatusBadRequest {
		t.Fatalf("unknown agent: %d", code)
	}
	if got := tokenNamespaces(t, h.st, "box"); !slices.Equal(got, []string{"prod"}) {
		t.Fatalf("after refused edits: %v", got)
	}
	// Needs the CSRF token, and a logged-in admin.
	if resp := h.post("/tokens/box/namespaces", url.Values{"ns": {"lab"}}); resp.StatusCode != http.StatusForbidden {
		t.Fatalf("without csrf: %d", resp.StatusCode)
	}
	anon := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	resp, err := anon.PostForm(h.ts.URL+"/tokens/box/namespaces", url.Values{"ns": {"lab"}})
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode == http.StatusSeeOther && strings.Contains(resp.Header.Get("Location"), "msg=namespaces") || resp.StatusCode == 200 {
		t.Fatalf("anonymous edit: %d", resp.StatusCode)
	}
	if got := tokenNamespaces(t, h.st, "box"); !slices.Equal(got, []string{"prod"}) {
		t.Fatalf("after unauthorised edits: %v", got)
	}
}
