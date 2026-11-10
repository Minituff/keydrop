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
