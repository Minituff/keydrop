//go:build e2e

package e2e

import (
	"encoding/json"
	"net/url"
	"strings"
	"testing"
)

// TestMCP runs `keydrop mcp` as an MCP client would: JSON-RPC lines on
// stdin, replies on stdout. It lists keys and requests one for the admin,
// and a stored secret's value appears nowhere in what it prints. The
// token expires in 30 days, so the CLI warns, on stderr only.
func TestMCP(t *testing.T) {
	in := newInstance(t, binary)
	in.start(t, binary)
	pin := in.pin(t)
	web := setupAndLogin(t, in)
	secret := fakeSecret(t)
	web.addEntry(t, "mcp", "STORED_KEY", secret, "secret", "a key the agent may use")
	web.addEntry(t, "mcp", "BASE_URL", "https://api.example.com", "variable", "")
	g := newAgent(t, binary)
	g.login(t, in.url, pin, web.postToken(t, url.Values{"name": {"mcp-agent"}, "namespaces": {"mcp"}, "lifetime": {"30"}}))

	msgs := []string{
		`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"e2e","version":"0"}}}`,
		`{"jsonrpc":"2.0","method":"notifications/initialized"}`,
		`{"jsonrpc":"2.0","id":2,"method":"tools/list"}`,
		`{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"keydrop_secrets","arguments":{}}}`,
		`{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"keydrop_request","arguments":{"names":["NEEDED_BY_MCP"],"description":"fake-e2e-mcp-request"}}}`,
		`{"jsonrpc":"2.0","id":5,"method":"tools/call","params":{"name":"keydrop_info","arguments":{"ref":"STORED_KEY"}}}`,
		`{"jsonrpc":"2.0","id":6,"method":"tools/call","params":{"name":"keydrop_vars","arguments":{}}}`,
	}
	r := g.run(t, strings.Join(msgs, "\n")+"\n", "mcp")
	if r.code != 0 {
		t.Fatalf("keydrop mcp: exit %d, stderr %s", r.code, r.stderr)
	}
	noLeak(t, "keydrop mcp", r.all(), secret)
	if !strings.Contains(r.stderr, "this token expires in") {
		t.Errorf("no expiry warning on stderr: %q", r.stderr)
	}

	var replies []map[string]any
	for _, l := range strings.SplitAfter(r.stdout, "\n") {
		if l == "" {
			continue
		}
		var m map[string]any
		if !strings.HasSuffix(l, "\n") || json.Unmarshal([]byte(l), &m) != nil || m["jsonrpc"] != "2.0" {
			t.Fatalf("stdout holds something other than a JSON-RPC line: %q", l)
		}
		replies = append(replies, m)
	}
	if len(replies) != 6 { // the notification gets none
		t.Fatalf("%d replies: %s", len(replies), r.stdout)
	}
	result := func(i int) map[string]any {
		res, ok := replies[i]["result"].(map[string]any)
		if !ok || replies[i]["id"] != float64(i+1) {
			t.Fatalf("reply %d: %v", i, replies[i])
		}
		return res
	}
	text := func(i int) string {
		res := result(i)
		if res["isError"] != false {
			t.Fatalf("reply %d is an error: %v", i, res)
		}
		return res["content"].([]any)[0].(map[string]any)["text"].(string)
	}
	if info := result(0)["serverInfo"].(map[string]any); info["name"] != "keydrop" || result(0)["protocolVersion"] != "2025-06-18" {
		t.Errorf("initialize: %v", result(0))
	}
	if tools := result(1)["tools"].([]any); len(tools) != 6 {
		t.Errorf("tools/list: %d tools", len(tools))
	}
	if s := text(2); !strings.Contains(s, "mcp/STORED_KEY") || !strings.Contains(s, "a key the agent may use") || strings.Contains(s, "BASE_URL") {
		t.Errorf("keydrop_secrets: %q", s)
	}
	if s := text(3); !strings.Contains(s, "Requested. The human can fill it in here:") || !strings.Contains(s, "keydrop wait NEEDED_BY_MCP") {
		t.Errorf("keydrop_request: %q", s)
	}
	if s := text(4); !strings.Contains(s, "mcp/STORED_KEY") || !strings.Contains(s, "updated") {
		t.Errorf("keydrop_info: %q", s)
	}
	if s := text(5); !strings.Contains(s, "mcp/BASE_URL=https://api.example.com") {
		t.Errorf("keydrop_vars: %q", s)
	}
	if _, page := web.get(t, "/inbox"); !strings.Contains(page, "NEEDED_BY_MCP") || !strings.Contains(page, "fake-e2e-mcp-request") {
		t.Error("the request made through MCP isn't in the admin's Inbox")
	}
	in.stop(t)
}
