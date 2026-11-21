//go:build e2e

package e2e

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// keydrop guard runs as a Claude Code PreToolUse hook on machines that
// may not be paired: with an empty HOME and no KEYDROP_* settings it still
// answers, from the hook's JSON alone.
func TestGuard(t *testing.T) {
	g := newAgent(t, binary)
	hook := func(command string) string {
		b, err := json.Marshal(map[string]any{
			"session_id":      "e2e",
			"hook_event_name": "PreToolUse",
			"tool_name":       "Bash",
			"tool_input":      map[string]string{"command": command},
		})
		if err != nil {
			t.Fatal(err)
		}
		return string(b)
	}
	const pasted = "sk-e2e-FAKE-not-a-real-key-0000"

	if r := g.run(t, hook("keydrop secrets && make test"), "guard"); r.code != 0 || r.all() != "" {
		t.Errorf("fine command: exit %d, output %q", r.code, r.all())
	}
	for _, cmd := range []string{
		"keydrop get X --raw",
		"cd /tmp && ~/.local/bin/keydrop get " + pasted + " --raw",
		"keydrop run --no-mask -e X -- make",
		"keydrop run -e X -- sh -c 'printenv X'",
	} {
		r := g.run(t, hook(cmd), "guard")
		if r.code != 2 || r.stdout != "" || !strings.HasPrefix(r.stderr, "Blocked: ") || strings.Count(r.stderr, "\n") != 1 {
			t.Errorf("%q: exit %d, stdout %q, stderr %q; want exit 2 and one Blocked: line", cmd, r.code, r.stdout, r.stderr)
		}
		noLeak(t, "guard reason", r.stderr, pasted)
	}
	// Fails open on input it can't read, and ignores other tools.
	for _, in := range []string{"", "not json", `{"tool_name":"Write","tool_input":{"command":"keydrop get X --raw"}}`} {
		if r := g.run(t, in, "guard"); r.code != 0 {
			t.Errorf("input %q: exit %d, want 0 (%s)", in, r.code, r.all())
		}
	}
	// --command checks a string instead.
	if r := g.run(t, "", "guard", "--command", "keydrop get X --raw"); r.code != 2 {
		t.Errorf("--command: exit %d, want 2", r.code)
	}
	// It never touched the (empty) config directory.
	if _, err := os.Stat(filepath.Join(g.home, ".config")); !os.IsNotExist(err) {
		t.Errorf("guard created or read %s: %v", filepath.Join(g.home, ".config"), err)
	}
}
