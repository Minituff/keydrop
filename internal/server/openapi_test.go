package server

import (
	"encoding/json"
	"net/http"
	"os"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/minituff/keydrop/internal/store"
)

// docs/openapi.json describes the agent API by hand. These tests fail when
// it and the server disagree, so a new or changed route can't ship without
// it.

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

// TestOpenAPIAuth checks the document's unauthenticated operations are
// exactly the routes that answer without a token, by asking each route
// with none: one behind agentAuth says "missing bearer token".
func TestOpenAPIAuth(t *testing.T) {
	h := newHarness(t)
	doc := loadOpenAPI(t)
	ops := openAPIOps(doc)
	var open []string
	for _, r := range apiRoutes(h.srv) {
		method, path, _ := strings.Cut(r, " ")
		path = strings.NewReplacer("{ns}", "lab", "{name}", "API_KEY", "{file}", "keydrop-linux-amd64").Replace(path)
		code, m, _ := h.api(method, path, "", nil)
		if code != http.StatusUnauthorized || m["error"] != "missing bearer token" {
			open = append(open, r)
		}
		op := ops[r]
		if op == nil {
			continue // TestOpenAPIMatchesRoutes reports it
		}
		sec, ok := op["security"]
		if !ok {
			sec = doc["security"]
		}
		reqs, _ := sec.([]any)
		noAuth := len(reqs) == 0
		bearer := slices.ContainsFunc(reqs, func(x any) bool { _, ok := x.(map[string]any)["bearerAuth"]; return ok })
		switch isOpen := slices.Contains(open, r); {
		case isOpen && !noAuth:
			t.Errorf("%s answers without a token, but docs/openapi.json says it needs one (give it \"security\": [])", r)
		case !isOpen && !bearer:
			t.Errorf("%s needs a token, but docs/openapi.json doesn't say so (give it \"security\": [{\"bearerAuth\": []}])", r)
		}
	}
	// AGENTS.md: "The only unauthenticated API endpoints are /api/v1/pair
	// and /api/v1/pair/poll". A new one needs the maintainer first.
	want := append([]string{"POST /api/v1/pair", "POST /api/v1/pair/poll"}, openAPIHelpers...)
	slices.Sort(want)
	slices.Sort(open)
	if !slices.Equal(open, want) {
		t.Errorf("routes answering without a token: %v, want %v", open, want)
	}
}

func TestOpenAPIDocument(t *testing.T) {
	raw, err := os.ReadFile(openAPIFile)
	if err != nil {
		t.Fatal(err)
	}
	// Nothing in the agent API tells a canary from an ordinary secret, so
	// nothing in its description may mention one.
	if strings.Contains(strings.ToLower(string(raw)), "canary") {
		t.Error("docs/openapi.json mentions canaries; agents must not be able to tell one from an ordinary secret")
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

// TestOpenAPILive calls the real server and checks each answer's top-level
// fields against the document: none undeclared, every required one there.
// It doesn't validate types; it catches a renamed, added or dropped field.
func TestOpenAPILive(t *testing.T) {
	h := newHarness(t)
	h.setup()
	doc := loadOpenAPI(t)
	tok, err := h.st.CreateToken("box", []string{"lab"}, store.PermWrite, nil)
	if err != nil {
		t.Fatal(err)
	}
	soon := time.Now().Add(48 * time.Hour)
	h.st.PutValue("lab", "API_KEY", []byte("fake-value-123"), &store.Meta{Description: "example", Usage: "example", Expires: &soon})
	h.st.PutValue("lab", "BASE_URL", []byte("https://api.example.com"), &store.Meta{Variable: true})

	check := func(method, pattern, path, token string, body any, want int) map[string]any {
		t.Helper()
		code, m, raw := h.api(method, path, token, body)
		if code != want {
			t.Fatalf("%s %s: %d %s, want %d", method, path, code, raw, want)
		}
		op := openAPIOps(doc)[method+" "+pattern]
		resps, _ := op["responses"].(map[string]any)
		r := openAPIResolve(doc, resps[strconv.Itoa(code)])
		content, _ := r["content"].(map[string]any)
		media, _ := content["application/json"].(map[string]any)
		schema := openAPIResolve(doc, media["schema"])
		if schema == nil {
			t.Fatalf("%s %s: docs/openapi.json has no JSON schema for its %d response: %s", method, pattern, code, openAPIHint)
		}
		var v any
		json.Unmarshal(raw, &v)
		items := []any{v}
		if schema["type"] == "array" {
			items, _ = v.([]any)
			schema = openAPIResolve(doc, schema["items"])
			if len(items) == 0 {
				t.Errorf("%s %s: empty list, so nothing was checked", method, path)
			}
		}
		props, _ := schema["properties"].(map[string]any)
		for _, it := range items {
			obj, _ := it.(map[string]any)
			for k := range obj {
				if props[k] == nil {
					t.Errorf("%s %s %d: field %q isn't in docs/openapi.json: add it to that response's schema (and docs/api.md)", method, pattern, code, k)
				}
			}
			req, _ := schema["required"].([]any)
			for _, k := range req {
				if _, ok := obj[k.(string)]; !ok {
					t.Errorf("%s %s %d: docs/openapi.json requires %q, but the answer has none", method, pattern, code, k)
				}
			}
		}
		return m
	}
	const sec = "/api/v1/secrets/{ns}/{name}"
	check("GET", "/api/v1/whoami", "/api/v1/whoami", tok, nil, 200)
	check("GET", "/api/v1/whoami", "/api/v1/whoami", "kd_EXAMPLE", nil, 401)
	check("POST", sec+"/status", "/api/v1/secrets/lab/API_KEY/status", tok, map[string]string{"status": "leaked"}, 200)
	check("POST", sec+"/flag", "/api/v1/secrets/lab/API_KEY/flag", tok, map[string]string{"reason": "stopped working"}, 201)
	check("POST", sec+"/notes", "/api/v1/secrets/lab/API_KEY/notes", tok, map[string]string{"text": "used by the DNS job"}, 201)
	check("GET", "/api/v1/secrets", "/api/v1/secrets", tok, nil, 200)
	check("GET", sec, "/api/v1/secrets/lab/API_KEY", tok, nil, 200)
	check("GET", sec, "/api/v1/secrets/other/API_KEY", tok, nil, 404)
	check("POST", sec+"/reveal", "/api/v1/secrets/lab/API_KEY/reveal?purpose=test", tok, nil, 200)
	check("POST", sec+"/ack", "/api/v1/secrets/lab/BASE_URL/ack", tok, nil, 200)
	check("PUT", sec, "/api/v1/secrets/lab/NEW_KEY", tok, map[string]any{"value": "fake-value-456", "description": "example"}, 200)
	check("POST", "/api/v1/requests", "/api/v1/requests", tok, map[string]string{"name": "WANTED"}, 201)
	check("POST", "/api/v1/requests/batch", "/api/v1/requests/batch", tok, map[string]any{"names": []string{"ONE", "TWO"}}, 201)
	check("GET", "/api/v1/expiring", "/api/v1/expiring?days=7", tok, nil, 200)
	check("GET", "/api/v1/history", "/api/v1/history", tok, nil, 200)
	check("GET", "/api/v1/token/renew", "/api/v1/token/renew", tok, nil, 200)
	check("POST", "/api/v1/cli/upgrade", "/api/v1/cli/upgrade", tok, map[string]string{"from": "1.0.0"}, 200)
	p := check("POST", "/api/v1/pair", "/api/v1/pair", "", map[string]string{"host": "box", "user": "me"}, 201)
	check("POST", "/api/v1/pair/poll", "/api/v1/pair/poll", "", map[string]any{"poll": p["poll"]}, 200)
}
