//go:build unix

package client

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Without a home or XDG_CONFIG_HOME there's no config directory, rather
// than one relative to wherever keydrop runs. Everything can still come
// from the environment.
func TestNoConfigDirWithoutHome(t *testing.T) {
	cwd := t.TempDir()
	t.Chdir(cwd)
	os.MkdirAll(filepath.Join(cwd, ".config", "keydrop"), 0o700)
	os.WriteFile(filepath.Join(cwd, ".config", "keydrop", "url"), []byte("https://chosen-by-checkout.example\n"), 0o600)
	os.WriteFile(filepath.Join(cwd, ".config", "keydrop", "token"), []byte("kd_fake\n"), 0o600)
	for _, xdg := range []string{"", "relative/dir", "."} {
		t.Setenv("HOME", "")
		t.Setenv("XDG_CONFIG_HOME", xdg)
		t.Setenv("KEYDROP_URL", "")
		t.Setenv("KEYDROP_TOKEN", "")
		t.Setenv("KEYDROP_TLS_PIN", "")
		if _, err := ConfigDir(); !errors.Is(err, ErrNoConfigDir) {
			t.Fatalf("XDG_CONFIG_HOME=%q: %v", xdg, err)
		}
		_, err := FromEnv()
		if !errors.Is(err, ErrNoConfigDir) || !strings.Contains(err.Error(), "set HOME") {
			t.Fatalf("XDG_CONFIG_HOME=%q: %v", xdg, err)
		}
		t.Setenv("KEYDROP_URL", "https://10.0.0.5:8443")
		if _, err := FromEnv(); !errors.Is(err, ErrNoConfigDir) {
			t.Fatalf("no token source: %v", err)
		}
		t.Setenv("KEYDROP_TOKEN", "kd_fake-env")
		c, err := FromEnv()
		if err != nil || c.URL != "https://10.0.0.5:8443" || c.Token != "kd_fake-env" || c.pin != "" {
			t.Fatalf("all from the environment: %+v %v", c, err)
		}
	}
}

func setupConfig(t *testing.T) string {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	t.Setenv("KEYDROP_URL", "")
	t.Setenv("KEYDROP_TOKEN", "")
	t.Setenv("KEYDROP_TOKEN_FILE", "")
	t.Setenv("KEYDROP_TLS_PIN", "")
	dir, err := ConfigDir()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	for name, v := range map[string]string{"url": "https://10.0.0.5:8443", "token": "kd_fake", "pin": "sha256:00"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(v+"\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := FromEnv(); err != nil {
		t.Fatalf("a private config directory: %v", err)
	}
	return dir
}

// A config directory, url or pin that others can write is refused: what's
// in them decides where the token goes and which certificate is trusted.
func TestConfigWritableByOthers(t *testing.T) {
	dir := setupConfig(t)
	for _, mode := range []os.FileMode{0o770, 0o707, 0o777} {
		os.Chmod(dir, mode)
		_, err := FromEnv()
		if err == nil || !strings.Contains(err.Error(), "chmod 700 "+dir) {
			t.Errorf("dir mode %v: %v", mode, err)
		}
		if _, err := ConfigDir(); err == nil {
			t.Errorf("dir mode %v: ConfigDir accepted it", mode)
		}
	}
	// Readable by others is fine for the directory: the token file has
	// its own check.
	os.Chmod(dir, 0o755)
	if _, err := FromEnv(); err != nil {
		t.Errorf("dir 0755: %v", err)
	}
	os.Chmod(dir, 0o700)
	for _, name := range []string{"url", "pin"} {
		path := filepath.Join(dir, name)
		for _, mode := range []os.FileMode{0o620, 0o602, 0o666} {
			os.Chmod(path, mode)
			_, err := FromEnv()
			if err == nil || !strings.Contains(err.Error(), "chmod 600 "+path) {
				t.Errorf("%s mode %v: %v", name, mode, err)
			}
		}
		os.Chmod(path, 0o644) // readable is fine: they aren't secret
		if _, err := FromEnv(); err != nil {
			t.Errorf("%s 0644: %v", name, err)
		}
		os.Chmod(path, 0o600)
	}
	// The pin from a loose directory isn't read even when the URL comes
	// from the environment.
	t.Setenv("KEYDROP_URL", "https://10.0.0.5:8443")
	t.Setenv("KEYDROP_TOKEN", "kd_fake")
	os.Chmod(dir, 0o777)
	if _, err := FromEnv(); err == nil {
		t.Error("read the pin from a world-writable directory")
	}
	os.Chmod(dir, 0o700)
}

// A config directory or file another user owns is refused. Changing an
// owner needs root, so this runs only as root.
func TestConfigOwnedByAnotherUser(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("needs root to give a file to another user")
	}
	dir := setupConfig(t)
	const nobody = 65534
	if err := os.Chown(filepath.Join(dir, "url"), nobody, nobody); err != nil {
		t.Skip(err)
	}
	if _, err := FromEnv(); err == nil || !strings.Contains(err.Error(), "belongs to another user") {
		t.Errorf("url owned by another user: %v", err)
	}
	os.Chown(filepath.Join(dir, "url"), 0, 0)
	os.Chown(dir, nobody, nobody)
	if _, err := FromEnv(); err == nil || !strings.Contains(err.Error(), "belongs to another user") {
		t.Errorf("directory owned by another user: %v", err)
	}
	os.Chown(dir, 0, 0)
}
