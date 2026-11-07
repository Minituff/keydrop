package server

import (
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/minituff/keydrop/internal/store"
)

func TestParsePasteAndMap(t *testing.T) {
	names := []string{"EXAMPLE_API_KEY", "EXAMPLE_API_SECRET", "EXAMPLE_URL"}
	file := "# downloaded from the router\n\nkey=\"k-123\" # comment\r\nexport secret='s=456=='\nexample_url: https://router.example/api\n"
	lines, err := parsePaste(file)
	if err != nil {
		t.Fatal(err)
	}
	got, err := mapPaste(lines, names)
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]string{"EXAMPLE_API_KEY": "k-123", "EXAMPLE_API_SECRET": "s=456==", "EXAMPLE_URL": "https://router.example/api"}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("%s: %q, want %q", k, got[k], v)
		}
	}
	bad := map[string]string{
		"no separator":   "key=a\njust-a-value-hunter2\n",
		"no key":         "=hunter2\n",
		"empty value":    "key=\n",
		"no match":       "token=hunter2\n",
		"two names":      "api=hunter2\n",
		"twice":          "key=a\nEXAMPLE_API_KEY=hunter2\n",
		"nothing at all": "# only a comment\n",
		"unclosed quote": "key=\"hunter2\n",
		"after quote":    "key=\"hunter2\" junk\n",
		"escaped quote":  "key=\"hun\\\"ter2\"\n",
		"inline comment": "key=hunter2 # the key\n",
	}
	ambiguous := []string{"A_API", "B_API", "EXAMPLE_API_KEY"}
	for name, text := range bad {
		lines, err := parsePaste(text)
		if err == nil {
			n := names
			if name == "two names" {
				n = ambiguous
			}
			_, err = mapPaste(lines, n)
		}
		if err == nil {
			t.Errorf("%s: accepted", name)
			continue
		}
		if strings.Contains(err.Error(), "hunter2") || strings.Contains(err.Error(), "token") {
			t.Errorf("%s: the error shows the line: %v", name, err)
		}
		if !strings.Contains(err.Error(), "nothing was saved") {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func TestPasteMistake(t *testing.T) {
	for _, v := range []string{"KEY=abc", "export API_KEY=abc", "api_key: abc", "secret = abc", "a\nb"} {
		if pasteMistake(v, false) == "" {
			t.Errorf("%q not caught", v)
		}
	}
	for _, v := range []string{"dGVzdA==", "dGVzdDE=", "abc==", "user:pass", "https://x.example/?a=b", "ghp_abc123", "p@ss=word"} {
		if h := pasteMistake(v, false); h != "" {
			t.Errorf("%q caught: %s", v, h)
		}
	}
	if pasteMistake("line one\nline two", true) != "" {
		t.Error("newline with keep whitespace")
	}
}

func (h *harness) form(path string, form url.Values) (int, string) {
	h.t.Helper()
	form.Set("csrf", h.csrf())
	resp := h.post(path, form)
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	if resp.StatusCode == http.StatusSeeOther {
		_, body := h.get(resp.Header.Get("Location"))
		return resp.StatusCode, body
	}
	return resp.StatusCode, string(b)
}

func TestBatchRequestAndFill(t *testing.T) {
	h := newHarness(t)
	h.setup()
	tok := h.createToken("bot", "lab")
	body := map[string]any{"namespace": "lab", "names": []string{"EXAMPLE_API_KEY", "EXAMPLE_API_SECRET", "EXAMPLE_URL"}, "group": "Router <b>", "description": "router api"}
	code, m, raw := h.api("POST", "/api/v1/requests/batch", tok, body)
	if code != http.StatusCreated {
		t.Fatalf("batch: %d %s", code, raw)
	}
	id, _ := m["batch"].(string)
	if id == "" || len(m["refs"].([]any)) != 3 {
		t.Fatalf("batch reply: %s", raw)
	}
	// Too many, and over the open-request cap, are refused whole.
	many := make([]string, store.MaxBatch+1)
	for i := range many {
		many[i] = "K" + string(rune('A'+i))
	}
	if code, _, _ := h.api("POST", "/api/v1/requests/batch", tok, map[string]any{"names": many}); code != http.StatusBadRequest {
		t.Fatalf("too many: %d", code)
	}
	_, dash := h.get("/inbox")
	for _, want := range []string{`id="batch-` + id + `"`, `request batch-card`, `name="value.EXAMPLE_API_KEY"`, `name="kind.EXAMPLE_URL"`, `class="paste-file"`, "Save all", `value="Router &lt;b&gt;"`, "agent-written"} {
		if !strings.Contains(dash, want) {
			t.Fatalf("dashboard lacks %s", want)
		}
	}
	if strings.Contains(dash, "Router <b>") {
		t.Fatal("agent label not escaped")
	}
	fill := func(extra url.Values) (int, string) {
		f := url.Values{"namespace": {"lab"}, "name": {"EXAMPLE_API_KEY", "EXAMPLE_API_SECRET", "EXAMPLE_URL"}}
		for k, v := range extra {
			f[k] = v
		}
		return h.form("/requests/fill", f)
	}
	// Both the paste box and a field: refused.
	if code, body := fill(url.Values{"paste": {"key=pasted-key-1"}, "value.EXAMPLE_URL": {"https://router.example"}}); code != http.StatusBadRequest || !strings.Contains(body, "not both") {
		t.Fatalf("both: %d", code)
	}
	// A line that doesn't map: refused, no value shown.
	if code, body := fill(url.Values{"paste": {"key=pasted-key-1\nbogus=pasted-bogus-1"}}); code != http.StatusBadRequest || !strings.Contains(body, "line 2") || strings.Contains(body, "pasted-") {
		t.Fatalf("unmapped line: %d", code)
	}
	// A whole line pasted into a field: refused with a hint.
	if code, body := fill(url.Values{"value.EXAMPLE_API_KEY": {"key=pasted-key-1"}}); code != http.StatusBadRequest || !strings.Contains(body, "whole line") || strings.Contains(body, "pasted-key-1") {
		t.Fatalf("whole line: %d", code)
	}
	if sec, _ := h.st.GetSecret("lab", "EXAMPLE_API_KEY"); !sec.Pending {
		t.Fatal("a refused form saved something")
	}
	// The paste fills two; the third stays open. The group box isn't
	// ticked, so the agent's label isn't used.
	code, body2 := fill(url.Values{"paste": {"key=pasted-key-1\nsecret=\"pasted-secret-1\"\n"}, "kind.EXAMPLE_API_KEY": {"variable"}, "groupname": {"Router <b>"}})
	if code != http.StatusSeeOther || !strings.Contains(body2, "Saved EXAMPLE_API_KEY, EXAMPLE_API_SECRET.") || strings.Contains(body2, "pasted-secret-1") {
		t.Fatalf("paste fill: %d %s", code, body2)
	}
	k, _ := h.st.GetSecret("lab", "EXAMPLE_API_KEY")
	u, _ := h.st.GetSecret("lab", "EXAMPLE_URL")
	if k.Pending || !k.Variable || k.Group != "" || !u.Pending || len(h.st.Groups("")) != 0 {
		t.Fatalf("after paste: %+v %+v", k, u)
	}
	if v, _, _ := h.st.Reveal("lab", "EXAMPLE_API_SECRET", "test"); string(v) != "pasted-secret-1" {
		t.Fatalf("secret value %q", v)
	}
	// The last one, with the group ticked: made and assigned.
	code, _ = fill(url.Values{"name": {"EXAMPLE_URL"}, "value.EXAMPLE_URL": {"https://router.example"}, "kind.EXAMPLE_URL": {"variable"}, "group": {"yes"}, "groupname": {"Router"}})
	if code != http.StatusSeeOther {
		t.Fatalf("group fill: %d", code)
	}
	g, ok := h.st.FindGroup("lab", "Router")
	if u, _ := h.st.GetSecret("lab", "EXAMPLE_URL"); !ok || u.Group != g.Slug || u.Pending {
		t.Fatalf("grouped fill: %+v %+v", u, g)
	}
	// "Save it exactly as pasted" overrides the guard.
	h.api("POST", "/api/v1/requests", tok, map[string]string{"namespace": "lab", "name": "CONN"})
	if code, _ := h.form("/requests/fill", url.Values{"namespace": {"lab"}, "name": {"CONN"}, "value.CONN": {"Server=db;Password=x"}, "exact": {"yes"}}); code != http.StatusSeeOther {
		t.Fatalf("exact: %d", code)
	}
	audit, _ := os.ReadFile(filepath.Join(h.dir, "audit.jsonl"))
	for _, leak := range []string{"pasted-", "https://router.example", "Password=x", "Router <b>"} {
		if strings.Contains(string(audit), leak) {
			t.Fatalf("audit log holds %q", leak)
		}
	}
	for _, want := range []string{"group.create", "group.assign", "group.propose", "fulfilled request from bot"} {
		if !strings.Contains(string(audit), want) {
			t.Fatalf("audit log lacks %s", want)
		}
	}
	// The API lists the group.
	_, _, list := h.api("GET", "/api/v1/secrets", tok, nil)
	if !strings.Contains(string(list), `"group":{"slug":"router","name":"Router"`) {
		t.Fatalf("list: %s", list)
	}
}

func TestSingleValueGuard(t *testing.T) {
	h := newHarness(t)
	h.setup()
	add := func(v url.Values) int {
		f := url.Values{"namespace": {"lab"}, "name": {"A"}, "kind": {"secret"}}
		for k, x := range v {
			f[k] = x
		}
		code, _ := h.form("/secrets", f)
		return code
	}
	if code := add(url.Values{"value": {"EXAMPLE_API_KEY=abc"}}); code != http.StatusBadRequest {
		t.Fatalf("whole line: %d", code)
	}
	if code := add(url.Values{"value": {"two\nlines"}}); code != http.StatusBadRequest {
		t.Fatalf("newline: %d", code)
	}
	if code := add(url.Values{"value": {"dGVzdDE="}}); code != http.StatusSeeOther {
		t.Fatalf("base64: %d", code)
	}
	if code, _ := h.form("/secret/lab/A/value", url.Values{"value": {"key: abc"}}); code != http.StatusBadRequest {
		t.Fatalf("set value: %d", code)
	}
	if code, _ := h.form("/secret/lab/A/value", url.Values{"value": {"key: abc"}, "exact": {"yes"}}); code != http.StatusSeeOther {
		t.Fatalf("set value exactly: %d", code)
	}
}

func TestGroupPages(t *testing.T) {
	h := newHarness(t)
	h.setup()
	for _, n := range []string{"CF_TOKEN", "CF_ZONE", "OTHER"} {
		h.st.PutValue("lab", n, []byte("value-"+n), nil)
	}
	_, dash := h.get("/")
	if !strings.Contains(dash, `data-auto="true"`) || !strings.Contains(dash, `group-header`) || !strings.Contains(dash, `entry-row`) {
		t.Fatal("no auto group on the dashboard")
	}
	if code, _ := h.form("/groups", url.Values{"namespace": {"lab"}, "name": {"DNS"}, "color": {"teal"}}); code != http.StatusSeeOther {
		t.Fatalf("create: %d", code)
	}
	if code, _ := h.form("/groups", url.Values{"namespace": {"lab"}, "name": {"x"}, "color": {"mauve"}}); code != http.StatusBadRequest {
		t.Fatalf("bad colour: %d", code)
	}
	if code, _ := h.form("/secret/lab/OTHER/group", url.Values{"group": {"dns"}}); code != http.StatusSeeOther {
		t.Fatalf("assign: %d", code)
	}
	if code, _ := h.form("/groups/lab/dns", url.Values{"name": {"Domains"}, "color": {"blue"}}); code != http.StatusSeeOther {
		t.Fatalf("rename: %d", code)
	}
	_, dash = h.get("/")
	if !strings.Contains(dash, "color-blue") || !strings.Contains(dash, "Domains") {
		t.Fatal("renamed group not shown")
	}
	if code, _ := h.form("/groups/promote", url.Values{"namespace": {"lab"}, "prefix": {"CF"}}); code != http.StatusSeeOther {
		t.Fatalf("promote: %d", code)
	}
	if code, _ := h.form("/groups/lab/dns/delete", url.Values{}); code != http.StatusBadRequest {
		t.Fatalf("delete without confirm: %d", code)
	}
	if code, _ := h.form("/groups/lab/dns/delete", url.Values{"confirm": {"yes"}}); code != http.StatusSeeOther {
		t.Fatalf("delete: %d", code)
	}
	if sec, ok := h.st.GetSecret("lab", "OTHER"); !ok || sec.Group != "" {
		t.Fatal("entry gone or still grouped")
	}
	if code, _ := h.form("/settings/autogroups", url.Values{}); code != http.StatusSeeOther || h.st.AutoGroups() {
		t.Fatalf("auto off: %d", code)
	}
	// Forms need the CSRF token.
	resp := h.post("/groups", url.Values{"namespace": {"lab"}, "name": {"NoCSRF"}})
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("no csrf: %d", resp.StatusCode)
	}
	audit, _ := os.ReadFile(filepath.Join(h.dir, "audit.jsonl"))
	for _, want := range []string{"group.create", "group.update", "group.assign", "group.delete", "settings.autogroups"} {
		if !strings.Contains(string(audit), want) {
			t.Fatalf("audit log lacks %s", want)
		}
	}
	for _, leak := range []string{"value-CF"} {
		if strings.Contains(dash, leak) || strings.Contains(string(audit), leak) {
			t.Fatal("a secret value leaked")
		}
	}
}

// Agents, even read-only ones, can request a batch, but nothing in the
// API makes or assigns groups.
func TestReadOnlyTokenCantGroup(t *testing.T) {
	h := newHarness(t)
	h.setup()
	tok := h.createToken("reader", "lab")
	code, _, raw := h.api("POST", "/api/v1/requests/batch", tok, map[string]any{"names": []string{"A_ONE", "A_TWO"}, "group": "Evil"})
	if code != http.StatusCreated {
		t.Fatalf("batch: %d %s", code, raw)
	}
	if len(h.st.Groups("")) != 0 {
		t.Fatal("a proposed label made a group")
	}
	// The admin forms want a session: a token gets the login page.
	h.st.CreateGroup("lab", "Real", "red", "")
	for _, p := range []string{"/groups", "/secret/lab/A_ONE/group", "/requests/fill", "/groups/promote"} {
		req, _ := http.NewRequest("POST", h.ts.URL+p, strings.NewReader(url.Values{"namespace": {"lab"}, "name": {"Evil"}, "group": {"real"}, "prefix": {"A"}}.Encode()))
		req.Header.Set("Authorization", "Bearer "+tok)
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		resp, err := http.DefaultTransport.RoundTrip(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusSeeOther || resp.Header.Get("Location") != "/login" {
			t.Fatalf("%s with a token: %d %s", p, resp.StatusCode, resp.Header.Get("Location"))
		}
	}
	if len(h.st.Groups("")) != 1 {
		t.Fatal("a token made a group")
	}
	if sec, _ := h.st.GetSecret("lab", "A_ONE"); sec.Group != "" || !sec.Pending {
		t.Fatalf("after token posts: %+v", sec)
	}
}

// A batch of N counts N against the write limit, all or none.
func TestBatchRateLimit(t *testing.T) {
	l := newRateLimit(5, 3600e9)
	now := time.Now()
	if !l.allowN("t", 4, now) || l.allowN("t", 2, now) || !l.allow("t", now) || l.allow("t", now) {
		t.Fatal("allowN")
	}
}

// The agent's proposed label never heads the card (only the marked
// agent-text block and the unticked group box show it), each request
// links to its page (where it can be deleted), and the batch link the
// agent gets points at the inbox, where the card is.
func TestBatchCardLabelAndLinks(t *testing.T) {
	h := newHarness(t)
	h.setup()
	h.srv.cfg.PublicURL = "https://secrets.example.com"
	tok := h.createToken("bot", "lab")
	body := map[string]any{"namespace": "lab", "names": []string{"ONE_KEY", "TWO_KEY"}, "group": "Approved By Admin"}
	code, m, raw := h.api("POST", "/api/v1/requests/batch", tok, body)
	if code != http.StatusCreated {
		t.Fatalf("batch: %d %s", code, raw)
	}
	if u, _ := m["url"].(string); u != "https://secrets.example.com/inbox#batch-"+m["batch"].(string) {
		t.Fatalf("batch url %q", u)
	}
	_, page := h.get("/inbox")
	if strings.Contains(page, "<b>Approved By Admin</b>") {
		t.Fatal("the agent's label heads the card")
	}
	if !strings.Contains(page, "<b>lab</b>") {
		t.Fatal("card title")
	}
	if strings.Contains(page, `name="group" value="yes" checked`) {
		t.Fatal("group box ticked for the admin")
	}
	for _, n := range []string{"ONE_KEY", "TWO_KEY"} {
		if !strings.Contains(page, `href="/secret/lab/`+n+`"`) {
			t.Fatalf("no link to %s", n)
		}
	}
	// Saving without ticking the box ignores the prefilled name.
	code, _ = h.form("/requests/fill", url.Values{"namespace": {"lab"}, "name": {"ONE_KEY", "TWO_KEY"},
		"value.ONE_KEY": {"fake-one"}, "groupname": {"Approved By Admin"}})
	if code != http.StatusSeeOther && code != http.StatusOK {
		t.Fatalf("fill: %d", code)
	}
	if gs := h.srv.store.Groups("lab"); len(gs) != 0 {
		t.Fatalf("group made without the box ticked: %+v", gs)
	}
	// A search cut at 100 characters keeps whole characters.
	_, page = h.get("/?q=" + url.QueryEscape(strings.Repeat("é", 150)))
	if !strings.Contains(page, strings.Repeat("é", 100)+`"`) {
		t.Fatal("query not cut at 100 characters")
	}
}
