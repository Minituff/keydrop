package server

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/minituff/keydrop/internal/store"
)

// rawCall is one agent call with the whole answer: status, headers without
// Date, and body.
func (h *harness) rawCall(method, path, token string, body any) (int, http.Header, string) {
	h.t.Helper()
	var rd io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rd = bytes.NewReader(b)
	}
	req, _ := http.NewRequest(method, h.ts.URL+path, rd)
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		h.t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	resp.Header.Del("Date")
	return resp.StatusCode, resp.Header, string(b)
}

func canaryHits(st *store.Store) int {
	n := 0
	list, _ := st.CanaryHits()
	for _, c := range list {
		n += c.Count
	}
	return n
}

// limitHarness has lab/REAL1 and lab/DECOY (a canary) with the same value,
// both limited to the write token "allowed"; "barred" (write) has lab too,
// and lab/OPEN has no limit. The clock is frozen so both keys' timestamps
// match.
func limitHarness(t *testing.T) (h *harness, allowed, barred string) {
	h = newHarness(t)
	h.setup()
	h.clock()
	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	var err error
	allowed, err = h.st.CreateToken("allowed", []string{"lab"}, store.PermWrite, nil)
	must(err)
	barred, err = h.st.CreateToken("barred", []string{"lab"}, store.PermWrite, nil)
	must(err)
	for _, k := range []string{"REAL1", "DECOY", "OPEN"} {
		must(h.st.PutValue("lab", k, []byte("fake-limited-value"), nil))
	}
	must(h.st.SetCanary("lab", "DECOY", true))
	for _, k := range []string{"REAL1", "DECOY"} {
		must(h.st.SetLimit("lab", k, true, []string{"allowed"}))
	}
	return h, allowed, barred
}

// For a token on the list and one off it, every call on a limited canary
// answers exactly as on a limited ordinary secret (status, headers, body),
// and each call but a metadata read is a touch, refused ones included.
func TestLimitCanaryIndistinguishable(t *testing.T) {
	h, allowed, barred := limitHarness(t)
	wh := h.webhook()
	for _, tok := range []struct {
		name, tok string
		reveal    int
	}{{"barred", barred, http.StatusForbidden}, {"allowed", allowed, http.StatusOK}} {
		for _, c := range []struct {
			name, method, path string
			body               any
			touch              bool
			want               int
		}{
			{"metadata", "GET", "", nil, false, http.StatusOK},
			{"reveal", "POST", "/reveal", nil, true, tok.reveal},
			{"ack", "POST", "/ack", nil, true, tok.reveal},
			{"flag", "POST", "/flag", map[string]any{"reason": "looks odd"}, true, http.StatusCreated},
			{"status", "POST", "/status", map[string]any{"status": "leaked"}, true, http.StatusOK},
			{"note", "POST", "/notes", map[string]any{"text": "used for dns"}, true, http.StatusCreated},
			{"put", "PUT", "", map[string]any{"value": "fake-limited-value", "overwrite": true}, true, tok.reveal},
			{"put new", "PUT", "", map[string]any{"value": "fake-limited-value"}, true, map[bool]int{true: http.StatusForbidden, false: http.StatusConflict}[tok.name == "barred"]},
			{"put variable", "PUT", "", map[string]any{"value": "plain", "variable": true, "overwrite": true}, true, http.StatusForbidden},
		} {
			before := canaryHits(h.st)
			dc, dh, db := h.rawCall(c.method, "/api/v1/secrets/lab/DECOY"+c.path, tok.tok, c.body)
			if want := before + map[bool]int{true: 1}[c.touch]; canaryHits(h.st) != want {
				t.Fatalf("%s %s: touches %d, want %d", tok.name, c.name, canaryHits(h.st), want)
			}
			rc, rh, rb := h.rawCall(c.method, "/api/v1/secrets/lab/REAL1"+c.path, tok.tok, c.body)
			if canaryHits(h.st) != before+map[bool]int{true: 1}[c.touch] {
				t.Fatalf("%s %s: an ordinary secret counted as a touch", tok.name, c.name)
			}
			if dc != c.want || dc != rc || !headersEqual(dh, rh) || strings.ReplaceAll(db, "DECOY", "REAL1") != rb {
				t.Fatalf("%s %s: canary %d %v %s\nordinary %d %v %s", tok.name, c.name, dc, dh, db, rc, rh, rb)
			}
			if strings.Contains(db, "fake-limited-value") != (c.name == "reveal" && tok.name == "allowed") {
				t.Fatalf("%s %s: value in the answer: %s", tok.name, c.name, db)
			}
		}
		// Both in the list, alike.
		_, _, list := h.rawCall("GET", "/api/v1/secrets", tok.tok, nil)
		var all []map[string]any
		json.Unmarshal([]byte(list), &all)
		var got []string
		for _, s := range all {
			if s["name"] != "OPEN" {
				b, _ := json.Marshal(s)
				got = append(got, strings.ReplaceAll(string(b), "DECOY", "REAL1"))
			}
		}
		if len(got) != 2 || got[0] != got[1] {
			t.Fatalf("%s: list entries differ: %v", tok.name, got)
		}
	}
	// One alert per canary and token, the barred token's included.
	alerts := strings.Join(wh.all(h.srv.alerts), "\n")
	if !strings.Contains(alerts, "token `barred`") || !strings.Contains(alerts, "token `allowed`") {
		t.Fatalf("alerts: %s", alerts)
	}
}

func headersEqual(a, b http.Header) bool {
	if len(a) != len(b) {
		return false
	}
	for k, v := range a {
		if !slices.Equal(v, b[k]) {
			return false
		}
	}
	return true
}

// What a token off the list gets: usable:false in metadata and lists (and
// nothing new for a key without a limit, or for a token on the list), a
// 403 naming only itself, the denied read in the audit log, counted in
// the reveal limit; nothing new to read; still flags and status.
func TestLimitAPI(t *testing.T) {
	h, allowed, barred := limitHarness(t)
	open, _, before := h.api("GET", "/api/v1/secrets/lab/OPEN", barred, nil)
	if open != http.StatusOK || strings.Contains(string(before), "usable") {
		t.Fatalf("a key without a limit: %s", before)
	}
	if _, m, raw := h.api("GET", "/api/v1/secrets/lab/REAL1", barred, nil); m["usable"] != false || m["new"] != false {
		t.Fatalf("barred: %s", raw)
	}
	if _, m, raw := h.api("GET", "/api/v1/secrets/lab/REAL1", allowed, nil); strings.Contains(string(raw), "usable") || m["new"] != true {
		t.Fatalf("allowed: %s", raw)
	}
	if _, _, raw := h.api("GET", "/api/v1/secrets?new=1", barred, nil); strings.Contains(string(raw), "REAL1") || !strings.Contains(string(raw), "OPEN") {
		t.Fatalf("new for barred: %s", raw)
	}
	code, m, _ := h.api("POST", "/api/v1/secrets/lab/REAL1/reveal?purpose=deploy", barred, nil)
	msg, _ := m["error"].(string)
	if code != http.StatusForbidden || !strings.Contains(msg, "limited to other agents") || !strings.Contains(msg, "barred") || strings.Contains(msg, "allowed") {
		t.Fatalf("reveal: %d %q", code, msg)
	}
	ev := h.srv.audit.Recent(1)[0]
	if ev.Action != "secret.read.denied" || ev.Target != "lab/REAL1" || ev.Actor != "token:barred" || ev.Detail != "limited to other agents; agent says: deploy" {
		t.Fatalf("audit: %+v", ev)
	}
	// Refused reveals count in the reveal limit.
	h.srv.reveals = newRateLimit(2, time.Hour)
	h.api("POST", "/api/v1/secrets/lab/REAL1/reveal", barred, nil)
	h.api("POST", "/api/v1/secrets/lab/REAL1/reveal", barred, nil)
	if code, _, _ := h.api("POST", "/api/v1/secrets/lab/OPEN/reveal", barred, nil); code != http.StatusTooManyRequests {
		t.Fatalf("after two refused reveals: %d", code)
	}
	h.srv.reveals = newRateLimit(revealsPerHour, time.Hour)
	// An empty list is nobody; the allowed token reads.
	if err := h.st.SetLimit("lab", "OPEN", true, nil); err != nil {
		t.Fatal(err)
	}
	for _, tok := range []string{allowed, barred} {
		if code, _, _ := h.api("POST", "/api/v1/secrets/lab/OPEN/reveal", tok, nil); code != http.StatusForbidden {
			t.Fatalf("empty list: %d", code)
		}
	}
	if code, m, _ := h.api("POST", "/api/v1/secrets/lab/REAL1/reveal", allowed, nil); code != http.StatusOK || m["value"] != "fake-limited-value" {
		t.Fatalf("allowed reveal: %d", code)
	}
	// An add token can't replace a key it created once it's limited away.
	adder, _ := h.st.CreateToken("adder", []string{"lab"}, store.PermAdd, nil)
	if code, _, _ := h.api("PUT", "/api/v1/secrets/lab/MINE", adder, map[string]any{"value": "fake-mine-1"}); code != http.StatusOK {
		t.Fatalf("add: %d", code)
	}
	h.st.SetLimit("lab", "MINE", true, []string{"allowed"})
	if code, _, _ := h.api("PUT", "/api/v1/secrets/lab/MINE", adder, map[string]any{"value": "fake-mine-2", "overwrite": true}); code != http.StatusForbidden {
		t.Fatalf("add token over its own limited key: %d", code)
	}
	// Flag and status still work for the barred token.
	if code, _, _ := h.api("POST", "/api/v1/secrets/lab/MINE/status", barred, map[string]any{"status": "leaked"}); code != http.StatusOK {
		t.Fatalf("status: %d", code)
	}
	// Namespace isolation comes first: no namespace, 404 as ever.
	other, _ := h.st.CreateToken("other", []string{"elsewhere"}, store.PermWrite, nil)
	for _, p := range []string{"", "/reveal", "/ack"} {
		method := map[bool]string{true: "GET", false: "POST"}[p == ""]
		if code, _, _ := h.api(method, "/api/v1/secrets/lab/REAL1"+p, other, nil); code != http.StatusNotFound {
			t.Fatalf("%s without the namespace: %d", p, code)
		}
	}
	if code, _, _ := h.api("PUT", "/api/v1/secrets/lab/REAL1", other, map[string]any{"value": "x", "overwrite": true}); code != http.StatusForbidden {
		t.Fatalf("put without the namespace: %d", code)
	}
}

// The form on a key's page: an admin form (CSRF, logged in), logged with
// the agents' names, accepting only agents that have the namespace; the
// page then names only the agents that can use the key.
func TestLimitAdminForm(t *testing.T) {
	h := newHarness(t)
	h.setup()
	h.st.PutValue("lab", "ROOT_KEY", []byte("fake-root-value"), nil)
	h.st.PutValue("lab", "SOME_URL", []byte("https://x.test"), &store.Meta{Variable: true})
	h.createToken("alpha", "lab")
	h.createToken("bravo", "lab")
	h.createToken("zulu", "elsewhere")
	readers := func() string {
		t.Helper()
		_, page := h.get("/secret/lab/ROOT_KEY")
		if strings.Contains(page, "fake-root-value") {
			t.Fatal("value on the page")
		}
		i := strings.Index(page, "Agents that can read it")
		return stripTags(page[i : i+strings.Index(page[i:], "</dd>")])
	}
	if got := readers(); !strings.Contains(got, "alpha") || !strings.Contains(got, "bravo") {
		t.Fatalf("readers before: %q", got)
	}
	if resp := h.post("/secret/lab/ROOT_KEY/limit", url.Values{"only": {"yes"}, "token": {"alpha"}}); resp.StatusCode != http.StatusForbidden {
		t.Fatalf("without csrf: %d", resp.StatusCode)
	}
	if code, _ := h.form("/secret/lab/ROOT_KEY/limit", url.Values{"only": {"yes"}, "token": {"alpha", "zulu"}}); code != http.StatusBadRequest {
		t.Fatalf("an agent without the namespace: %d", code)
	}
	if sec, _ := h.st.GetSecret("lab", "ROOT_KEY"); sec.Limit != nil {
		t.Fatal("a refused form set a limit")
	}
	code, page := h.form("/secret/lab/ROOT_KEY/limit", url.Values{"only": {"yes"}, "token": {"alpha"}})
	if code != http.StatusSeeOther || !strings.Contains(page, "Saved which agents may use it.") || !strings.Contains(page, `name="token" value="alpha" checked`) || strings.Contains(page, `value="bravo" checked`) {
		t.Fatalf("limit: %d", code)
	}
	if got := readers(); !strings.Contains(got, "alpha") || strings.Contains(got, "bravo") {
		t.Fatalf("readers with the limit: %q", got)
	}
	if !h.auditHas("secret.limit", "only: alpha") {
		t.Fatal("not logged")
	}
	if _, dash := h.get("/"); !strings.Contains(dash, `<span class="chip">limited</span>`) {
		t.Fatal("no badge on the list")
	}
	h.form("/secret/lab/ROOT_KEY/limit", url.Values{"only": {"yes"}})
	if got := readers(); !strings.Contains(got, "limited to no agent") || !h.auditHas("secret.limit", "only: no agent") {
		t.Fatalf("readers with an empty limit: %q", got)
	}
	h.form("/secret/lab/ROOT_KEY/limit", url.Values{"only": {"no"}, "token": {"alpha"}})
	if sec, _ := h.st.GetSecret("lab", "ROOT_KEY"); sec.Limit != nil || !h.auditHas("secret.limit", "any agent with the namespace") {
		t.Fatal("limit not lifted")
	}
	// Not offered for a variable, and refused if posted anyway.
	if _, page := h.get("/secret/lab/SOME_URL"); strings.Contains(page, "/limit") {
		t.Fatal("limit form on a variable")
	}
	if code, _ := h.form("/secret/lab/SOME_URL/limit", url.Values{"only": {"yes"}}); code != http.StatusBadRequest {
		t.Fatalf("limit a variable: %d", code)
	}
	// Logged out: nothing.
	h.web.Jar, _ = cookiejar.New(nil)
	if resp := h.post("/secret/lab/ROOT_KEY/limit", url.Values{"only": {"yes"}}); resp.StatusCode == http.StatusSeeOther && strings.Contains(resp.Header.Get("Location"), "msg=limit") {
		t.Fatal("logged out, but saved")
	}
	if sec, _ := h.st.GetSecret("lab", "ROOT_KEY"); sec.Limit != nil {
		t.Fatal("logged out, but saved")
	}
}
