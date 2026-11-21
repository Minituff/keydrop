package main

import (
	"bytes"
	"io"
	"log"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/minituff/keydrop/internal/audit"
	"github.com/minituff/keydrop/internal/client"
	"github.com/minituff/keydrop/internal/server"
	"github.com/minituff/keydrop/internal/store"
)

// limitedServer is a real server with lab/OPEN_KEY and lab/LIMITED_KEY,
// the second limited to an agent other than "bot". It returns bot's token.
func limitedServer(t *testing.T) (url, tok string) {
	t.Helper()
	log.SetOutput(io.Discard)
	t.Cleanup(func() { log.SetOutput(os.Stderr) })
	dir := t.TempDir()
	st, err := store.Open(dir, bytes.Repeat([]byte{9}, 32))
	if err != nil {
		t.Fatal(err)
	}
	al, _ := audit.Open(filepath.Join(dir, "audit.jsonl"))
	ts := httptest.NewServer(server.New(server.Config{}, st, al))
	t.Cleanup(ts.Close)
	tok, err = st.CreateToken("bot", []string{"lab"}, store.PermRead, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.CreateToken("other", []string{"lab"}, store.PermRead, nil); err != nil {
		t.Fatal(err)
	}
	st.PutValue("lab", "OPEN_KEY", []byte("fake-open-value-1"), nil)
	st.PutValue("lab", "LIMITED_KEY", []byte("fake-limited-value-1"), nil)
	if err := st.SetLimit("lab", "LIMITED_KEY", true, []string{"other"}); err != nil {
		t.Fatal(err)
	}
	return ts.URL, tok
}

// secrets, info and the MCP tools mark a key limited to other agents, and
// only that one.
func TestLimitedMarker(t *testing.T) {
	u, tok := limitedServer(t)
	c := client.New(u, tok, "")
	list, err := listKind(c, "secret", false, false, "")
	if err != nil {
		t.Fatal(err)
	}
	var b strings.Builder
	printList(&b, list)
	if !strings.Contains(b.String(), "lab/LIMITED_KEY  [limited to other agents]") || strings.Contains(b.String(), "lab/OPEN_KEY  [limited") {
		t.Fatalf("secrets: %q", b.String())
	}
	connect := func() (*client.Client, error) { return c, nil }
	for _, r := range mcpLines(t, connect, call(1, "keydrop_info", map[string]any{"ref": "LIMITED_KEY"}), call(2, "keydrop_secrets", map[string]any{})) {
		if text, isErr := toolText(t, r); isErr || !strings.Contains(text, "lab/LIMITED_KEY  [limited to other agents]") {
			t.Fatalf("mcp: %q", text)
		}
	}
}

// run with one limited key among others fails before the command starts,
// so no value reaches any environment, and prints the server's refusal.
func TestRunLimitedKey(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("needs sh")
	}
	u, tok := limitedServer(t)
	t.Setenv("KEYDROP_URL", u)
	t.Setenv("KEYDROP_TOKEN", tok)
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	marker := filepath.Join(t.TempDir(), "started")
	var code int
	var err error
	stdout, stderr := captureStd(t, func() {
		code, err = cmdRun([]string{"-e", "OPEN_KEY", "-e", "LIMITED_KEY", "--", "sh", "-c", "env > " + marker})
	})
	if err == nil || !strings.Contains(err.Error(), "lab/LIMITED_KEY is limited to other agents; ask the admin to allow bot on it") || strings.Contains(err.Error(), "other on") {
		t.Fatalf("run: %d %v", code, err)
	}
	if _, serr := os.Stat(marker); serr == nil {
		t.Fatal("the command started")
	}
	if strings.Contains(stdout+stderr+err.Error(), "fake-") {
		t.Fatal("a value was printed")
	}
}
