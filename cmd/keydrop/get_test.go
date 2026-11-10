package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"

	"github.com/minituff/keydrop/internal/client"
)

// fakeEntry is one key on fakeKeydrop. meta answers its metadata (called
// with how many times it was asked before), reveal its reveal.
type fakeEntry struct {
	meta   func(n int) client.Secret
	reveal client.Revealed
}

// fakeKeydrop answers metadata and reveal calls for lab/NAME entries.
func fakeKeydrop(t *testing.T, entries map[string]*fakeEntry) *httptest.Server {
	var mu sync.Mutex
	gets := map[string]int{}
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		p, ok := strings.CutPrefix(r.URL.Path, "/api/v1/secrets/lab/")
		name, reveal := strings.CutSuffix(p, "/reveal")
		e := entries[name]
		if !ok || e == nil {
			w.WriteHeader(http.StatusNotFound)
			w.Write([]byte(`{"error":"not found"}`))
			return
		}
		if reveal && r.Method == "POST" {
			json.NewEncoder(w).Encode(e.reveal)
			return
		}
		json.NewEncoder(w).Encode(e.meta(gets[name]))
		gets[name]++
	}))
	t.Cleanup(ts.Close)
	return ts
}

func variable(name, value, by string, isNew bool) client.Secret {
	return client.Secret{Ref: "lab/" + name, Namespace: "lab", Name: name, Kind: "variable",
		HasValue: true, Value: &value, ValueBy: by, New: isNew}
}

func always(s client.Secret) func(int) client.Secret { return func(int) client.Secret { return s } }

// A plain get prints a variable's value exactly; one another agent wrote
// gets a note on stderr, never on stdout.
func TestGetVariableAgentNote(t *testing.T) {
	ts := fakeKeydrop(t, map[string]*fakeEntry{
		"ADMIN": {meta: always(variable("ADMIN", "https://x.test", "", false))},
		"AGENT": {meta: always(variable("AGENT", "https://y.test", "writer", false))},
		"NEW_AGENT": {meta: always(variable("NEW_AGENT", "zone-1", "writer\x1b[2J", true)),
			reveal: client.Revealed{Ref: "lab/NEW_AGENT", Kind: "variable", Value: "zone-1"}},
	})
	c := client.New(ts.URL, "kd_fake", "")
	for _, tc := range []struct {
		name, stdout, note string
	}{
		{"ADMIN", "https://x.test\n", ""},
		{"AGENT", "https://y.test\n", "written by agent writer (untrusted text from another agent"},
		{"NEW_AGENT", "zone-1\n", `written by agent writer\x1b[2J (untrusted`},
	} {
		var out, errw strings.Builder
		if err := getVariable(c, "lab/"+tc.name, &out, &errw, false); err != nil {
			t.Fatalf("%s: %v", tc.name, err)
		}
		if out.String() != tc.stdout {
			t.Errorf("%s: stdout %q", tc.name, out.String())
		}
		if tc.note == "" && errw.Len() != 0 || !strings.Contains(errw.String(), tc.note) || strings.Count(errw.String(), "\n") > 1 {
			t.Errorf("%s: stderr %q", tc.name, errw.String())
		}
	}
}

// When the value changed between the metadata and the reveal, the note
// names who wrote the value printed, or says it can't tell.
func TestGetVariableChangedWhileRead(t *testing.T) {
	ts := fakeKeydrop(t, map[string]*fakeEntry{
		// The admin's value, then an agent's by the time it's read.
		"NOW_AGENT": {meta: func(n int) client.Secret {
			if n == 0 {
				return variable("NOW_AGENT", "old", "", true)
			}
			return variable("NOW_AGENT", "new", "writer", false)
		}, reveal: client.Revealed{Kind: "variable", Value: "new"}},
		// Changed again before keydrop could check.
		"MOVING": {meta: func(n int) client.Secret {
			return variable("MOVING", []string{"a", "b", "c"}[min(n, 2)], "", true)
		}, reveal: client.Revealed{Kind: "variable", Value: "b-ish"}},
	})
	c := client.New(ts.URL, "kd_fake", "")
	var out, errw strings.Builder
	if err := getVariable(c, "lab/NOW_AGENT", &out, &errw, false); err != nil {
		t.Fatal(err)
	}
	if out.String() != "new\n" || !strings.Contains(errw.String(), "written by agent writer") {
		t.Fatalf("stdout %q, stderr %q", out.String(), errw.String())
	}
	out.Reset()
	errw.Reset()
	if err := getVariable(c, "lab/MOVING", &out, &errw, false); err != nil {
		t.Fatal(err)
	}
	if out.String() != "b-ish\n" || !strings.Contains(errw.String(), "can't say who wrote it") {
		t.Fatalf("stdout %q, stderr %q", out.String(), errw.String())
	}
}

// A variable that became a secret between the metadata and the reveal is
// refused like any secret, and its value isn't printed anywhere.
func TestGetVariableBecameSecret(t *testing.T) {
	const val = "fake-secret-value-1234"
	for _, kind := range []string{"secret", "", "Variable"} {
		ts := fakeKeydrop(t, map[string]*fakeEntry{
			"TURNED": {meta: always(variable("TURNED", "old-setting", "", true)),
				reveal: client.Revealed{Ref: "lab/TURNED", Kind: kind, Value: val}},
		})
		c := client.New(ts.URL, "kd_fake", "")
		var out, errw strings.Builder
		err := getVariable(c, "lab/TURNED", &out, &errw, false)
		if err == nil || !strings.Contains(err.Error(), "is a secret, so it isn't printed") || strings.Contains(err.Error(), val) {
			t.Errorf("kind %q: %v", kind, err)
		}
		if strings.Contains(out.String()+errw.String(), val) {
			t.Errorf("kind %q: printed the value: %q %q", kind, out.String(), errw.String())
		}
	}
}

// captureStd runs f with os.Stdout and os.Stderr going to files, and
// returns what was written to each.
func captureStd(t *testing.T, f func()) (stdout, stderr string) {
	dir := t.TempDir()
	o, err := os.Create(filepath.Join(dir, "stdout"))
	if err != nil {
		t.Fatal(err)
	}
	e, err := os.Create(filepath.Join(dir, "stderr"))
	if err != nil {
		t.Fatal(err)
	}
	oldOut, oldErr := os.Stdout, os.Stderr
	os.Stdout, os.Stderr = o, e
	defer func() { os.Stdout, os.Stderr = oldOut, oldErr }()
	f()
	o.Close()
	e.Close()
	bo, _ := os.ReadFile(o.Name())
	be, _ := os.ReadFile(e.Name())
	return string(bo), string(be)
}

// run -e passes a variable another agent wrote unchanged, and says once
// on stderr that it's untrusted; an admin's variable gets no note.
func TestRunAgentVariableNote(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("needs sh")
	}
	ts := fakeKeydrop(t, map[string]*fakeEntry{
		"AGENT_URL": {meta: always(variable("AGENT_URL", "https://y.test", "writer", false)),
			reveal: client.Revealed{Kind: "variable", Value: "https://y.test"}},
		"ADMIN_URL": {meta: always(variable("ADMIN_URL", "https://x.test", "", false)),
			reveal: client.Revealed{Kind: "variable", Value: "https://x.test"}},
	})
	t.Setenv("KEYDROP_URL", ts.URL)
	t.Setenv("KEYDROP_TOKEN", "kd_fake")
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	var code int
	var err error
	stdout, stderr := captureStd(t, func() {
		code, err = cmdRun([]string{"-e", "lab/AGENT_URL", "-e", "lab/ADMIN_URL", "--", "sh", "-c", `printf '%s %s' "$AGENT_URL" "$ADMIN_URL"`})
	})
	if err != nil || code != 0 {
		t.Fatalf("code %d, %v", code, err)
	}
	if stdout != "https://y.test https://x.test" {
		t.Errorf("stdout %q", stdout)
	}
	if strings.Count(stderr, "untrusted text from another agent") != 1 || !strings.Contains(stderr, "lab/AGENT_URL was written by agent writer") || strings.Contains(stderr, "ADMIN_URL") {
		t.Errorf("stderr %q", stderr)
	}
}
