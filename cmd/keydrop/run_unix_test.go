//go:build unix

package main

import (
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/minituff/keydrop/internal/client"
)

// inheritedPipe opens a pipe the way a shell's 3>&1 hands one to keydrop:
// not close-on-exec. It returns the read end and the write end's number.
func inheritedPipe(t *testing.T) (*os.File, int) {
	var p [2]int
	if err := syscall.Pipe(p[:]); err != nil {
		t.Fatal(err)
	}
	r := os.NewFile(uintptr(p[0]), "pipe-r")
	syscall.CloseOnExec(p[0])
	t.Cleanup(func() { r.Close() })
	return r, p[1]
}

// readAfterClose closes the write end (only here: closing it twice could
// close a descriptor that reused the number) and returns what was written.
func readAfterClose(t *testing.T, r *os.File, w int) string {
	syscall.Close(w)
	b, _ := io.ReadAll(r)
	return string(b)
}

// A descriptor keydrop inherited doesn't reach the command, so the command
// can't write a secret around the masking.
func TestRunDoesntPassInheritedFDs(t *testing.T) {
	const val = "fake-secret-value-for-fd-test"
	ts := fakeKeydrop(t, map[string]*fakeEntry{
		"S": {meta: always(client.Secret{Ref: "lab/S", Namespace: "lab", Name: "S", Kind: "secret", HasValue: true}),
			reveal: client.Revealed{Ref: "lab/S", Kind: "secret", Value: val}},
	})
	t.Setenv("KEYDROP_URL", ts.URL)
	t.Setenv("KEYDROP_TOKEN", "kd_fake")
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())

	// The setup is real: without keydrop, a child does get the descriptor.
	r, w := inheritedPipe(t)
	if err := exec.Command("sh", "-c", fmt.Sprintf(`printf reached >/dev/fd/%d`, w)).Run(); err != nil {
		t.Fatal(err)
	}
	if got := readAfterClose(t, r, w); got != "reached" {
		t.Fatalf("control: the child didn't get the descriptor (%q)", got)
	}

	r, w = inheritedPipe(t)
	var code int
	var err error
	stdout, _ := captureStd(t, func() {
		code, err = cmdRun([]string{"-e", "lab/S", "--", "sh", "-c", fmt.Sprintf(`printf '%%s' "$S"; printf '%%s' "$S" >/dev/fd/%d`, w)})
	})
	if err != nil {
		t.Fatal(err)
	}
	if got := readAfterClose(t, r, w); got != "" {
		t.Fatalf("the command wrote %d bytes to an inherited descriptor", len(got))
	}
	if code == 0 {
		t.Error("writing to the closed descriptor should have failed")
	}
	if stdout != "[keydrop:lab/S]" {
		t.Errorf("stdout isn't just the placeholder (%d bytes)", len(stdout))
	}
}

// upgrade's trial run of a downloaded build gets no KEYDROP_* settings.
func TestProbeVersionWithoutKeydropEnv(t *testing.T) {
	t.Setenv("KEYDROP_TOKEN", "kd_fake-token")
	t.Setenv("KEYDROP_URL", "https://10.0.0.5:8443")
	t.Setenv("OTHER_SETTING", "kept")
	path := filepath.Join(t.TempDir(), "keydrop-new")
	script := "#!/bin/sh\necho \"keydrop v9-${KEYDROP_TOKEN:-none}-${KEYDROP_URL:-none}-$OTHER_SETTING\"\n"
	if err := os.WriteFile(path, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	v, err := probeVersion(path)
	if err != nil || v != "v9-none-none-kept" || strings.Contains(v, "kd_fake") {
		t.Fatalf("%q %v", v, err)
	}
}

// stdinFake serves the secrets the --stdin tests use and points the CLI
// at it.
func stdinFake(t *testing.T, secrets map[string]string) {
	t.Helper()
	entries := map[string]*fakeEntry{}
	for name, v := range secrets {
		entries[name] = &fakeEntry{meta: always(client.Secret{Ref: "lab/" + name, Namespace: "lab", Name: name, Kind: "secret", HasValue: true}),
			reveal: client.Revealed{Ref: "lab/" + name, Kind: "secret", Value: v}}
	}
	ts := fakeKeydrop(t, entries)
	t.Setenv("KEYDROP_URL", ts.URL)
	t.Setenv("KEYDROP_TOKEN", "kd_fake")
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
}

// withStdin runs f with os.Stdin reading s, as if keydrop's own stdin
// carried it.
func withStdin(t *testing.T, s string, f func()) {
	t.Helper()
	p := filepath.Join(t.TempDir(), "stdin")
	if err := os.WriteFile(p, []byte(s), 0o600); err != nil {
		t.Fatal(err)
	}
	in, err := os.Open(p)
	if err != nil {
		t.Fatal(err)
	}
	defer in.Close()
	old := os.Stdin
	os.Stdin = in
	defer func() { os.Stdin = old }()
	f()
}

// --stdin gives the command exactly the stored bytes (newlines and a NUL
// included, no newline added) and then EOF: keydrop's own stdin isn't
// forwarded, and the value isn't in the command's environment or argv.
func TestRunStdinExactBytes(t *testing.T) {
	const val = "fake-stdin-value\nsecond line\x00after-nul"
	stdinFake(t, map[string]string{"S": val})
	dir := t.TempDir()
	got, envOut, argsOut := filepath.Join(dir, "got"), filepath.Join(dir, "env"), filepath.Join(dir, "args")
	var code int
	var err error
	withStdin(t, "keydrop's own stdin\n", func() {
		captureStd(t, func() {
			code, err = cmdRun([]string{"--stdin", "lab/S", "--", "sh", "-c", `cat >"$1"; env >"$2"; printf '%s\n' "$0" "$@" >"$3"`, "arg0", got, envOut, argsOut})
		})
	})
	if err != nil || code != 0 {
		t.Fatalf("code %d, %v", code, err)
	}
	b, _ := os.ReadFile(got)
	if string(b) != val {
		t.Fatalf("the command read %d bytes, not the %d of the value (equal: %v)", len(b), len(val), string(b) == val)
	}
	for _, f := range []string{envOut, argsOut} {
		b, _ := os.ReadFile(f)
		if strings.Contains(string(b), "fake-stdin-value") {
			t.Errorf("the value is in %s", filepath.Base(f))
		}
	}
}

// A value piped with --stdin is masked in the output like an -e value,
// as is, in base64 and URL-encoded; --no-mask leaves it.
func TestRunStdinMasked(t *testing.T) {
	const val = "fake-stdin-secret-42/x+y"
	stdinFake(t, map[string]string{"S": val})
	script := `v=$(cat); printf '%s\n' "$v"; printf '%s' "$v" | base64; printf '%s\n' "$v" | sed 's,/,%2F,g; s,+,%2B,g' >&2`
	var code int
	var err error
	stdout, stderr := captureStd(t, func() {
		code, err = cmdRun([]string{"--stdin", "lab/S", "--", "sh", "-c", script})
	})
	if err != nil || code != 0 {
		t.Fatalf("code %d, %v", code, err)
	}
	if stdout != "[keydrop:lab/S]\n[keydrop:lab/S]\n" || stderr != "[keydrop:lab/S]\n" {
		t.Errorf("not masked: stdout %q, stderr %q", strings.ReplaceAll(stdout, val, "<VALUE>"), strings.ReplaceAll(stderr, val, "<VALUE>"))
	}

	stdout, _ = captureStd(t, func() {
		code, err = cmdRun([]string{"--no-mask", "--stdin", "lab/S", "--", "cat"})
	})
	if err != nil || code != 0 || stdout != val {
		t.Errorf("--no-mask: code %d, %v, stdout is the value: %v", code, err, stdout == val)
	}
}

// A command that never reads stdin, or closes it, or leaves a background
// process holding it, doesn't hang keydrop or kill it with SIGPIPE, and
// its exit code still comes through. The value is bigger than a pipe's
// buffer, so the write can't just finish into it.
func TestRunStdinNotRead(t *testing.T) {
	val := "fake-big-value-" + strings.Repeat("x", 300<<10)
	stdinFake(t, map[string]string{"S": val})
	for _, tc := range []struct {
		script string
		code   int
	}{
		{"exit 3", 3},
		{"exit 0", 0},
		{"exec 0<&-; sleep 0.2; exit 5", 5},
		{"head -c 10 >/dev/null; exit 6", 6},
		// A descendant keeps stdin open without reading it.
		{"(sleep 3 >/dev/null 2>&1 &); exit 4", 4},
	} {
		start := time.Now()
		var code int
		var err error
		captureStd(t, func() {
			code, err = cmdRun([]string{"--stdin", "lab/S", "--", "sh", "-c", tc.script})
		})
		if err != nil || code != tc.code {
			t.Errorf("%q: code %d, %v; want %d", tc.script, code, err, tc.code)
		}
		if d := time.Since(start); d > 2*time.Second {
			t.Errorf("%q: took %v", tc.script, d)
		}
	}
}

// --stdin composes with -e (the same key in both, too), and run with only
// --stdin is valid.
func TestRunStdinWithEnv(t *testing.T) {
	const pass, user = "fake-registry-password", "fake-registry-user"
	stdinFake(t, map[string]string{"PASS": pass, "USER_NAME": user})
	var code int
	var err error
	stdout, _ := captureStd(t, func() {
		code, err = cmdRun([]string{"--no-mask", "--stdin", "lab/PASS", "-e", "lab/USER_NAME", "-e", "P=lab/PASS", "--", "sh", "-c",
			`printf '%s|%s|%s|%s' "$(cat)" "$USER_NAME" "$P" "${PASS-unset}"`})
	})
	if err != nil || code != 0 {
		t.Fatalf("code %d, %v", code, err)
	}
	if want := pass + "|" + user + "|" + pass + "|unset"; stdout != want {
		t.Errorf("got %q, want %q", stdout, want)
	}
}

// --stdin takes one key's name: a second --stdin, a VAR=NAME form or a
// value is refused before anything is read, without echoing it.
func TestRunStdinFlagErrors(t *testing.T) {
	stdinFake(t, map[string]string{"S": "fake-value-1234"})
	for _, args := range [][]string{
		{"--stdin", "lab/S", "--stdin", "lab/S", "--", "true"},
		{"--stdin", "X=lab/S", "--", "true"},
		{"--stdin", "not a name: fake-pasted-value", "--", "true"},
		{"--stdin", "lab/S"},
	} {
		_, err := cmdRun(args)
		if err == nil {
			t.Errorf("%q: no error", args)
			continue
		}
		if strings.Contains(err.Error(), "fake-pasted-value") {
			t.Errorf("%q: the error echoes the flag: %v", args, err)
		}
	}
	if _, err := cmdRun([]string{"--stdin", "lab/S", "--stdin", "lab/S", "--", "true"}); err == nil || !strings.Contains(err.Error(), "only once") {
		t.Errorf("twice: %v", err)
	}
}

// -e still refuses a value with a NUL (an environment variable can't
// hold one), even when the same key also goes to stdin.
func TestRunStdinNULStillRefusedForEnv(t *testing.T) {
	stdinFake(t, map[string]string{"S": "fake\x00value-1234"})
	_, err := cmdRun([]string{"--stdin", "lab/S", "-e", "lab/S", "--", "true"})
	if err == nil || !strings.Contains(err.Error(), "NUL") {
		t.Fatalf("%v", err)
	}
}
