package server

import (
	"encoding/json"
	"fmt"
	"maps"
	"net/http"
	"net/url"
	"os"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/minituff/keydrop/internal/store"
)

// docs/openapi.json describes the agent API by hand. These tests fail when
// it and the server disagree on the routes, who may call them, the status
// codes and fields of the answers the live test gets (nested ones too) or
// the fields and query parameters it sends, so a new or changed route or
// field can't ship without it. Field types aren't checked.

const openAPIFile = "../../docs/openapi.json"

// openAPIHelpers are the unauthenticated non-API routes docs/api.md lists,
// which the document covers too. The admin UI's routes are left out.
var openAPIHelpers = []string{"GET /healthz", "GET /setup.md", "GET /install.sh", "GET /cli/{file}"}

const openAPIHint = "describe every route under /api/v1/ in docs/openapi.json (and the table in docs/api.md) in the same change"

func loadOpenAPI(t *testing.T) map[string]any {
	t.Helper()
	b, err := os.ReadFile(openAPIFile)
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := json.Unmarshal(b, &doc); err != nil {
		t.Fatalf("docs/openapi.json isn't valid JSON: %v", err)
	}
	return doc
}

// apiRoutes are the registered routes the document must describe.
func apiRoutes(s *Server) []string {
	var out []string
	for _, p := range s.patterns {
		_, path, _ := strings.Cut(p, " ")
		if strings.HasPrefix(path, "/api/v1/") || slices.Contains(openAPIHelpers, p) {
			out = append(out, p)
		}
	}
	return out
}

// openAPIOps are the document's operations as "METHOD /path".
func openAPIOps(doc map[string]any) map[string]map[string]any {
	ops := map[string]map[string]any{}
	for path, item := range doc["paths"].(map[string]any) {
		for method, op := range item.(map[string]any) {
			ops[strings.ToUpper(method)+" "+path] = op.(map[string]any)
		}
	}
	return ops
}

func TestOpenAPIMatchesRoutes(t *testing.T) {
	h := newHarness(t)
	ops := openAPIOps(loadOpenAPI(t))
	routes := apiRoutes(h.srv)
	for _, r := range routes {
		if ops[r] == nil {
			t.Errorf("%s is a route but isn't in docs/openapi.json: %s", r, openAPIHint)
		}
	}
	for op := range ops {
		if !slices.Contains(routes, op) {
			t.Errorf("docs/openapi.json describes %s, which the server doesn't register: remove it or fix its method or path", op)
		}
	}
}

// openRoutes are every route that answers with neither a token nor the
// admin's session: AGENTS.md's two unauthenticated API endpoints (pairing),
// the helpers, and what login and first-run setup need. A new one needs
// the maintainer first.
var openRoutes = append([]string{
	"POST /api/v1/pair", "POST /api/v1/pair/poll",
	"GET /static/style.css", "GET /setup", "POST /setup", "GET /login", "POST /login",
}, openAPIHelpers...)

// TestOpenAPIAuth asks every registered route with no token and no
// session. One behind agentAuth says "missing bearer token", one behind
// the admin middleware sends the browser to log in (or to setup); the
// rest must be exactly openRoutes. The document's API operations must say
// which they are.
func TestOpenAPIAuth(t *testing.T) {
	h := newHarness(t)
	doc := loadOpenAPI(t)
	ops := openAPIOps(doc)
	noRedirect := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	// Asked before and after the admin's setup: /setup is open before, and
	// /login after.
	open := map[string]bool{}
	for _, setUp := range []bool{false, true} {
		if setUp {
			h.setup()
		}
		for _, r := range h.srv.patterns {
			method, path, _ := strings.Cut(r, " ")
			path = strings.NewReplacer("{$}", "", "{ns}", "lab", "{name}", "API_KEY", "{file}", "keydrop-linux-amd64",
				"{id}", "abc", "{slug}", "abc").Replace(path)
			req, _ := http.NewRequest(method, h.ts.URL+path, nil)
			resp, err := noRedirect.Do(req)
			if err != nil {
				t.Fatal(err)
			}
			var m map[string]any
			json.NewDecoder(resp.Body).Decode(&m)
			resp.Body.Close()
			loc := resp.Header.Get("Location")
			agent := resp.StatusCode == http.StatusUnauthorized && m["error"] == "missing bearer token"
			admin := resp.StatusCode == http.StatusSeeOther && (loc == "/login" || loc == "/setup")
			if !agent && !admin {
				open[r] = true
			}
			op := ops[r]
			if op == nil || !setUp {
				continue // not in the document, or asked already
			}
			sec, ok := op["security"]
			if !ok {
				sec = doc["security"]
			}
			reqs, _ := sec.([]any)
			noAuth := len(reqs) == 0
			bearer := slices.ContainsFunc(reqs, func(x any) bool { _, ok := x.(map[string]any)["bearerAuth"]; return ok })
			switch {
			case !agent && !noAuth:
				t.Errorf("%s answers without a token, but docs/openapi.json says it needs one (give it \"security\": [])", r)
			case agent && !bearer:
				t.Errorf("%s needs a token, but docs/openapi.json doesn't say so (give it \"security\": [{\"bearerAuth\": []}])", r)
			}
		}
	}
	got := slices.Sorted(maps.Keys(open))
	want := slices.Clone(openRoutes)
	slices.Sort(want)
	if !slices.Equal(got, want) {
		t.Errorf("routes answering with neither a token nor a session: %v, want %v", got, want)
	}
}

func TestOpenAPIDocument(t *testing.T) {
	raw, err := os.ReadFile(openAPIFile)
	if err != nil {
		t.Fatal(err)
	}
	// Nothing in the agent API tells a canary from an ordinary secret, so
	// nothing in its description may mention one, by any name.
	for _, w := range []string{"canar", "decoy", "honeypot", "honey pot", "tripwire", "trip wire"} {
		if strings.Contains(strings.ToLower(string(raw)), w) {
			t.Errorf("docs/openapi.json mentions %q; agents must not be able to tell a canary from an ordinary secret", w)
		}
	}
	doc := loadOpenAPI(t)
	if v, _ := doc["openapi"].(string); !strings.HasPrefix(v, "3.1") {
		t.Errorf("openapi is %q, want 3.1.x", v)
	}
	if v := doc["info"].(map[string]any)["version"]; v != strconv.Itoa(APILevel) {
		t.Errorf("info.version is %v, want APILevel %d: raise it with APILevel", v, APILevel)
	}
	walkRefs(doc, func(ref string) {
		if openAPIResolve(doc, ref) == nil {
			t.Errorf("$ref %s doesn't resolve", ref)
		}
	})
	ids := map[string]string{}
	headers := []string{"X-Keydrop-Version", "X-Keydrop-Api-Level", "X-Keydrop-Min-Cli-Level", "X-Keydrop-Self-Upgrade", "X-Keydrop-Token-Expires"}
	for name, op := range openAPIOps(doc) {
		id, _ := op["operationId"].(string)
		switch {
		case id == "":
			t.Errorf("%s has no operationId", name)
		case ids[id] != "":
			t.Errorf("operationId %s is used by %s and %s", id, ids[id], name)
		}
		ids[id] = name
		resps, _ := op["responses"].(map[string]any)
		if len(resps) == 0 {
			t.Errorf("%s has no responses", name)
		}
		if sec, ok := op["security"].([]any); ok && len(sec) == 0 {
			continue
		}
		// Authenticated answers carry the server's headers.
		for code, r := range resps {
			if code[0] != '2' {
				continue
			}
			hs, _ := openAPIResolve(doc, r)["headers"].(map[string]any)
			for _, hd := range headers {
				if hs[hd] == nil {
					t.Errorf("%s %s doesn't declare the %s header", name, code, hd)
				}
			}
		}
	}
}

func walkRefs(v any, f func(string)) {
	switch v := v.(type) {
	case map[string]any:
		if r, ok := v["$ref"].(string); ok {
			f(r)
		}
		for _, x := range v {
			walkRefs(x, f)
		}
	case []any:
		for _, x := range v {
			walkRefs(x, f)
		}
	}
}

// openAPIResolve follows v if it's a {"$ref": "#/..."} (or is the ref
// itself), or returns v as an object; nil when that fails.
func openAPIResolve(doc map[string]any, v any) map[string]any {
	ref, ok := v.(string)
	if m, isMap := v.(map[string]any); isMap {
		if ref, ok = m["$ref"].(string); !ok {
			return m
		}
	}
	if !ok || !strings.HasPrefix(ref, "#/") {
		return nil
	}
	var cur any = doc
	for _, part := range strings.Split(ref[2:], "/") {
		m, _ := cur.(map[string]any)
		if cur = m[part]; cur == nil {
			return nil
		}
	}
	m, _ := cur.(map[string]any)
	return openAPIResolve(doc, m)
}

// openAPIValue checks v, a decoded JSON answer, against schema: in every
// object, no field the schema doesn't declare and every field it requires;
// then into each field's own schema ($ref, nested object, array items), so
// Secret's status, flags, notes and group are checked too. Types aren't.
func openAPIValue(t *testing.T, doc map[string]any, where string, schema map[string]any, v any) {
	t.Helper()
	if schema = openAPIResolve(doc, schema); schema == nil || v == nil {
		return
	}
	switch v := v.(type) {
	case []any:
		items, _ := schema["items"].(map[string]any)
		for i, it := range v {
			openAPIValue(t, doc, fmt.Sprintf("%s[%d]", where, i), items, it)
		}
	case map[string]any:
		props, _ := schema["properties"].(map[string]any)
		if props == nil {
			return // a free-form object
		}
		for k, x := range v {
			sub, _ := props[k].(map[string]any)
			if sub == nil {
				t.Errorf("%s: field %q isn't in docs/openapi.json: add it to that schema (and docs/api.md)", where, k)
				continue
			}
			openAPIValue(t, doc, where+"."+k, sub, x)
		}
		req, _ := schema["required"].([]any)
		for _, k := range req {
			if _, ok := v[k.(string)]; !ok {
				t.Errorf("%s: docs/openapi.json requires %q, but the answer has none", where, k)
			}
		}
	}
}

// openAPIRequest checks what a live call sent against its operation: every
// field of the JSON body is a property of the requestBody schema, and every
// query parameter is declared.
func openAPIRequest(t *testing.T, doc, op map[string]any, where, path string, body any) {
	t.Helper()
	if body != nil {
		rb := openAPIResolve(doc, op["requestBody"])
		content, _ := rb["content"].(map[string]any)
		media, _ := content["application/json"].(map[string]any)
		schema := openAPIResolve(doc, media["schema"])
		if schema == nil {
			t.Errorf("%s: sends a JSON body, but docs/openapi.json has no requestBody schema for it", where)
		} else {
			var sent map[string]any
			b, _ := json.Marshal(body)
			json.Unmarshal(b, &sent)
			props, _ := schema["properties"].(map[string]any)
			for k := range sent {
				if props[k] == nil {
					t.Errorf("%s: request field %q isn't in docs/openapi.json's requestBody", where, k)
				}
			}
		}
	}
	if _, q, ok := strings.Cut(path, "?"); ok {
		vals, _ := url.ParseQuery(q)
		params, _ := op["parameters"].([]any)
		for k := range vals {
			if !slices.ContainsFunc(params, func(p any) bool {
				pm := openAPIResolve(doc, p)
				return pm["in"] == "query" && pm["name"] == k
			}) {
				t.Errorf("%s: query parameter %q isn't declared in docs/openapi.json", where, k)
			}
		}
	}
}

// TestOpenAPILive calls the real server and checks each answer against
// the document: its status code is declared, with a JSON schema; no field
// is undeclared and every required one is there, in nested objects too;
// and what the call sent (body fields, query parameters) is declared. It
// doesn't validate types; it catches a renamed, added or dropped field.
// Every answer that hands over a token is among the calls.
func TestOpenAPILive(t *testing.T) {
	h := newHarness(t)
	h.setup()
	h.srv.cfg.PublicURL = "https://secrets.example.com" // for the urls and links
	doc := loadOpenAPI(t)
	tok, err := h.st.CreateTokenExpiring("box", []string{"lab"}, store.PermWrite, nil, 30)
	if err != nil {
		t.Fatal(err)
	}
	other, err := h.st.CreateToken("other", []string{"lab"}, store.PermWrite, nil)
	if err != nil {
		t.Fatal(err)
	}
	soon := time.Now().Add(48 * time.Hour)
	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	must(h.st.PutValue("lab", "API_KEY", []byte("fake-value-123"), &store.Meta{Description: "example", Usage: "example", Expires: &soon}))
	must(h.st.PutValue("lab", "BASE_URL", []byte("https://api.example.com"), &store.Meta{Variable: true}))
	must(h.st.PutValue("lab", "ONLY_OTHER", []byte("fake-value-789"), nil))
	must(h.st.SetLimit("lab", "ONLY_OTHER", true, []string{"other"}))

	check := func(method, pattern, path, token string, body any, want int) map[string]any {
		t.Helper()
		where := method + " " + path
		op := openAPIOps(doc)[method+" "+pattern]
		if op == nil {
			t.Fatalf("%s: no operation %s %s in docs/openapi.json", where, method, pattern)
		}
		openAPIRequest(t, doc, op, where, path, body)
		code, m, raw := h.api(method, path, token, body)
		if code != want {
			t.Fatalf("%s: %d %s, want %d", where, code, raw, want)
		}
		resps, _ := op["responses"].(map[string]any)
		if resps[strconv.Itoa(code)] == nil {
			t.Fatalf("%s: docs/openapi.json doesn't declare the %d it answers: %s", where, code, openAPIHint)
		}
		r := openAPIResolve(doc, resps[strconv.Itoa(code)])
		content, _ := r["content"].(map[string]any)
		media, _ := content["application/json"].(map[string]any)
		schema := openAPIResolve(doc, media["schema"])
		if schema == nil {
			t.Fatalf("%s: docs/openapi.json has no JSON schema for its %d response: %s", where, code, openAPIHint)
		}
		var v any
		json.Unmarshal(raw, &v)
		if l, ok := v.([]any); ok && len(l) == 0 {
			t.Errorf("%s: empty list, so nothing was checked", where)
		}
		openAPIValue(t, doc, fmt.Sprintf("%s %d", where, code), schema, v)
		return m
	}
	const sec = "/api/v1/secrets/{ns}/{name}"
	check("GET", "/api/v1/whoami", "/api/v1/whoami", tok, nil, 200)
	check("GET", "/api/v1/whoami", "/api/v1/whoami", "kd_EXAMPLE", nil, 401)
	check("POST", sec+"/status", "/api/v1/secrets/lab/API_KEY/status", tok, map[string]string{"status": "replaced-by", "replaced_by": "BASE_URL"}, 200)
	check("POST", sec+"/flag", "/api/v1/secrets/lab/API_KEY/flag", tok, map[string]string{"reason": "stopped working", "link": "https://example.com/issue/1"}, 201)
	check("POST", sec+"/notes", "/api/v1/secrets/lab/API_KEY/notes", tok, map[string]string{"text": "used by the DNS job"}, 201)
	check("GET", "/api/v1/secrets", "/api/v1/secrets", tok, nil, 200)
	check("GET", sec, "/api/v1/secrets/lab/API_KEY", tok, nil, 200)
	check("GET", sec, "/api/v1/secrets/other/API_KEY", tok, nil, 404)
	check("POST", sec+"/reveal", "/api/v1/secrets/lab/API_KEY/reveal?purpose=test", tok, nil, 200)
	check("POST", sec+"/ack", "/api/v1/secrets/lab/BASE_URL/ack", tok, nil, 200)
	check("PUT", sec, "/api/v1/secrets/lab/NEW_KEY", tok, map[string]any{"value": "fake-value-456", "description": "example", "usage": "Bearer {}", "expires": "2030-01-01", "overwrite": true, "variable": false}, 200)
	check("POST", "/api/v1/requests", "/api/v1/requests", tok, map[string]string{"namespace": "lab", "name": "WANTED", "description": "please", "usage": "u"}, 201)
	check("POST", "/api/v1/requests/batch", "/api/v1/requests/batch", tok, map[string]any{"namespace": "lab", "names": []string{"ONE", "TWO"}, "description": "both", "group": "Example", "usage": "u"}, 201)
	check("GET", "/api/v1/expiring", "/api/v1/expiring?days=7", tok, nil, 200)
	check("GET", "/api/v1/history", "/api/v1/history?namespace=lab&name=API_KEY&limit=10", tok, nil, 200)
	check("POST", "/api/v1/cli/upgrade", "/api/v1/cli/upgrade", tok, map[string]string{"from": "1.0.0"}, 200)

	// A key with everything set: status, an open flag, an approved note,
	// a group, and a variable an agent wrote (value_by).
	sk, _ := h.st.GetSecret("lab", "API_KEY")
	must(h.st.ApproveNote("lab", "API_KEY", sk.Ext.Notes[0].ID, "used by the DNS job"))
	_, err = h.st.CreateGroup("lab", "Example", "", "")
	must(err)
	g := h.st.Groups("lab")
	must(h.st.SetEntryGroup("lab", "API_KEY", g[0].Slug))
	check("PUT", sec, "/api/v1/secrets/lab/AGENT_URL", other, map[string]any{"value": "https://agent.example", "variable": true}, 200)
	if m := check("GET", sec, "/api/v1/secrets/lab/API_KEY", tok, nil, 200); m["status"] == nil || m["flags"] == nil || m["notes"] == nil || m["group"] == nil {
		t.Fatalf("the full key lacks a field to check: %v", m)
	}
	if m := check("GET", sec, "/api/v1/secrets/lab/AGENT_URL", tok, nil, 200); m["value_by"] != "other" {
		t.Fatalf("no value_by: %v", m)
	}
	check("GET", "/api/v1/secrets", "/api/v1/secrets?new=1&namespace=lab", tok, nil, 200)
	check("GET", "/api/v1/secrets", "/api/v1/secrets?pending=1", tok, nil, 200)

	// A key limited to another agent, and one with no value yet.
	if m := check("GET", sec, "/api/v1/secrets/lab/ONLY_OTHER", tok, nil, 200); m["usable"] != false {
		t.Fatalf("not marked unusable: %v", m)
	}
	check("POST", sec+"/reveal", "/api/v1/secrets/lab/ONLY_OTHER/reveal", tok, nil, 403)
	check("POST", sec+"/ack", "/api/v1/secrets/lab/ONLY_OTHER/ack", tok, nil, 403)
	check("PUT", sec, "/api/v1/secrets/lab/ONLY_OTHER", tok, map[string]any{"value": "fake-value-000", "overwrite": true}, 403)
	check("POST", sec+"/reveal", "/api/v1/secrets/lab/WANTED/reveal", tok, nil, 409)

	// Renewal: ask, see it, then the admin rotates and the agent collects
	// the new token with the old one.
	check("POST", "/api/v1/token/renew", "/api/v1/token/renew", tok, nil, 200)
	check("GET", "/api/v1/token/renew", "/api/v1/token/renew", tok, nil, 200)
	_, err = h.st.RotateToken("box", 30)
	must(err)
	check("GET", "/api/v1/token/renew", "/api/v1/token/renew", tok, nil, 200)
	if m := check("POST", "/api/v1/token/collect", "/api/v1/token/collect", tok, nil, 200); m["token"] == nil {
		t.Fatal("collect handed over no token")
	}

	// Pairing, with a configured public URL (link), through approval.
	p := check("POST", "/api/v1/pair", "/api/v1/pair", "", map[string]string{"host": "box2", "user": "me"}, 201)
	if p["link"] == nil {
		t.Fatalf("no link with a public URL: %v", p)
	}
	check("POST", "/api/v1/pair/poll", "/api/v1/pair/poll", "", map[string]any{"poll": p["poll"]}, 200)
	if code, _ := h.form(p["path"].(string)+"/approve", url.Values{"name": {"box2"}, "namespaces": {"lab"}}); code != http.StatusSeeOther {
		t.Fatalf("approve: %d", code)
	}
	if m := check("POST", "/api/v1/pair/poll", "/api/v1/pair/poll", "", map[string]any{"poll": p["poll"]}, 200); m["token"] == nil {
		t.Fatalf("approved poll handed over no token: %v", m)
	}
}
