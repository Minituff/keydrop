package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestWarnPlainHTTP(t *testing.T) {
	for u, warn := range map[string]bool{
		"http://10.0.0.5:8443":        true,
		"HTTP://secrets.example.com":  true,
		"http://192.168.1.50":         true,
		"https://10.0.0.5:8443":       false,
		"http://127.0.0.1:8443":       false,
		"http://localhost:8443":       false,
		"http://[::1]:8443":           false,
		"https://secrets.example.com": false,
	} {
		var b strings.Builder
		warnPlainHTTP(&b, u)
		if got := strings.Contains(b.String(), "plain http"); got != warn {
			t.Errorf("%s: %q", u, b.String())
		}
	}
}

// login warns about plain http before asking for the token, like pair.
func TestLoginWarnsPlainHTTP(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	empty, err := os.Create(filepath.Join(t.TempDir(), "stdin"))
	if err != nil {
		t.Fatal(err)
	}
	defer empty.Close()
	old := os.Stdin
	os.Stdin = empty
	defer func() { os.Stdin = old }()
	for u, warn := range map[string]bool{"http://10.0.0.5:8443": true, "https://10.0.0.5:8443": false} {
		empty.Seek(0, 0)
		var err error
		_, stderr := captureStd(t, func() { err = cmdLogin([]string{"--url", u}) })
		if err == nil {
			t.Fatalf("%s: logged in with no token", u)
		}
		if got := strings.Contains(stderr, "plain http"); got != warn {
			t.Errorf("%s: stderr %q", u, stderr)
		}
	}
}
