package store

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func key32() []byte { return bytes.Repeat([]byte{7}, 32) }

func TestRoundTripAndAtRest(t *testing.T) {
	dir := t.TempDir()
	s, err := Open(dir, key32())
	if err != nil {
		t.Fatal(err)
	}
	if err := s.PutValue("lab", "CF", []byte("super-secret-123"), &Meta{Description: "dns"}); err != nil {
		t.Fatal(err)
	}
	raw, _ := os.ReadFile(filepath.Join(dir, stateFile))
	if bytes.Contains(raw, []byte("super-secret-123")) {
		t.Fatal("plaintext on disk")
	}
	fi, _ := os.Stat(filepath.Join(dir, stateFile))
	if fi.Mode().Perm() != 0o600 {
		t.Fatalf("state file mode %v", fi.Mode().Perm())
	}
	s2, err := Open(dir, key32())
	if err != nil {
		t.Fatal(err)
	}
	v, _, err := s2.Reveal("lab", "CF", "test")
	if err != nil || string(v) != "super-secret-123" {
		t.Fatalf("reveal: %q %v", v, err)
	}
	if _, err := Open(dir, bytes.Repeat([]byte{8}, 32)); err == nil {
		t.Fatal("wrong key accepted")
	}
}

// Ciphertext copied onto another secret's record must not decrypt.
func TestCiphertextBoundToName(t *testing.T) {
	dir := t.TempDir()
	s, _ := Open(dir, key32())
	s.PutValue("a", "ONE", []byte("value-one"), nil)
	s.PutValue("b", "TWO", []byte("value-two"), nil)
	s.mu.Lock()
	s.st.Secrets["b/TWO"].Value = s.st.Secrets["a/ONE"].Value
	s.mu.Unlock()
	if _, _, err := s.Reveal("b", "TWO", "x"); err == nil {
		t.Fatal("swapped ciphertext decrypted")
	}
}

func TestRollbackAndRequest(t *testing.T) {
	s, _ := Open(t.TempDir(), key32())
	if err := s.Request("lab", "GH", "need a PAT", "", "claude"); err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.Reveal("lab", "GH", "x"); err != ErrNoValue {
		t.Fatalf("want ErrNoValue, got %v", err)
	}
	s.PutValue("lab", "GH", []byte("v1-value"), nil)
	if sec, _ := s.GetSecret("lab", "GH"); sec.Pending || sec.Description != "need a PAT" || !sec.New {
		t.Fatalf("after fill: %+v", sec)
	}
	if err := s.Request("lab", "GH", "again", "", "claude"); err != ErrExists {
		t.Fatalf("re-request of filled secret: %v", err)
	}
	s.PutValue("lab", "GH", []byte("v2-value"), nil)
	s.Rollback("lab", "GH")
	if v, _, _ := s.Reveal("lab", "GH", "x"); string(v) != "v1-value" {
		t.Fatalf("rollback gave %q", v)
	}
	s.Rollback("lab", "GH")
	if v, _, _ := s.Reveal("lab", "GH", "x"); string(v) != "v2-value" {
		t.Fatalf("roll forward gave %q", v)
	}
}

func TestTokens(t *testing.T) {
	dir := t.TempDir()
	s, _ := Open(dir, key32())
	tok, err := s.CreateToken("claude", []string{"lab"}, false, nil)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := os.ReadFile(filepath.Join(dir, stateFile))
	if bytes.Contains(raw, []byte(tok)) {
		t.Fatal("token stored in plaintext")
	}
	got, err := s.LookupToken(tok, "10.0.0.5")
	if err != nil || got.Name != "claude" || !got.Allows("lab") || got.Allows("wedding") {
		t.Fatalf("lookup: %+v %v", got, err)
	}
	if _, err := s.LookupToken(tok+"x", "10.0.0.5"); err != ErrNotFound {
		t.Fatal("wrong token accepted")
	}
	s.RevokeToken("claude")
	if _, err := s.LookupToken(tok, "10.0.0.5"); err != ErrNotFound {
		t.Fatal("revoked token accepted")
	}
	var st state
	json.Unmarshal(raw, &st)
}

func TestNames(t *testing.T) {
	for _, ok := range []string{"a", "cloudflare-dns", "x.y_z-1"} {
		if !ValidName(ok) {
			t.Errorf("%q should be valid", ok)
		}
	}
	for _, bad := range []string{"", "A", "-x", "a/b", "a b", "../x"} {
		if ValidName(bad) {
			t.Errorf("%q should be invalid", bad)
		}
	}
	for _, ok := range []string{"A", "CLOUDFLARE_API_TOKEN", "_X", "GH_PAT_2"} {
		if !ValidSecretName(ok) {
			t.Errorf("secret %q should be valid", ok)
		}
	}
	for _, bad := range []string{"", "cf", "Cf_Token", "2FA", "A-B", "A.B", "A B", "A/B", "A=B", strings.Repeat("A", 65)} {
		if ValidSecretName(bad) {
			t.Errorf("secret %q should be invalid", bad)
		}
	}
	s, _ := Open(t.TempDir(), key32())
	if err := s.PutValue("lab", "cf", []byte("value-123"), nil); err != ErrBadSecret {
		t.Errorf("lowercase secret name: got %v", err)
	}
	if err := s.Request("lab", "gh-pat", "", "", "x"); err != ErrBadSecret {
		t.Errorf("request with old-style name: got %v", err)
	}
}

func TestVariableValue(t *testing.T) {
	s, _ := Open(t.TempDir(), key32())
	s.PutValue("lab", "API_URL", []byte("https://x.test"), &Meta{Variable: true})
	s.PutValue("lab", "API_KEY", []byte("fake-key-123"), nil)
	if v, err := s.VariableValue("lab", "API_URL"); err != nil || string(v) != "https://x.test" {
		t.Fatalf("variable: %q %v", v, err)
	}
	if v, err := s.VariableValue("lab", "API_KEY"); err != ErrNotVariable || v != nil {
		t.Fatalf("secret through VariableValue: %q %v", v, err)
	}
	s.Reveal("lab", "API_URL", "agent")
	if sec, _ := s.GetSecret("lab", "API_URL"); sec.LastReadAt != nil {
		t.Fatal("variable read recorded")
	}
	s.PutValue("lab", "API_URL", []byte("https://y.test"), nil)
	if sec, _ := s.GetSecret("lab", "API_URL"); !sec.Variable {
		t.Fatal("replacing the value changed the kind")
	}
}

// Kind belongs to each value: a secret overwritten by a variable comes back
// as a secret on rollback, never as a listed, unlogged variable.
func TestRollbackKeepsKind(t *testing.T) {
	s, _ := Open(t.TempDir(), key32())
	s.PutValue("lab", "GITHUB_PAT", []byte("fake-real-pat"), &Meta{})
	s.PutValue("lab", "GITHUB_PAT", []byte("junk"), &Meta{Variable: true})
	if err := s.Rollback("lab", "GITHUB_PAT"); err != nil {
		t.Fatal(err)
	}
	sec, _ := s.GetSecret("lab", "GITHUB_PAT")
	if sec.Variable {
		t.Fatal("rollback restored a secret value as a variable")
	}
	if v, err := s.VariableValue("lab", "GITHUB_PAT"); err != ErrNotVariable {
		t.Fatalf("secret readable as a variable: %q %v", v, err)
	}
	if v, variable, _ := s.Reveal("lab", "GITHUB_PAT", "x"); variable || string(v) != "fake-real-pat" {
		t.Fatalf("reveal after rollback: %q variable=%v", v, variable)
	}
	// And forward again: the junk value is a variable once more.
	s.Rollback("lab", "GITHUB_PAT")
	if sec, _ := s.GetSecret("lab", "GITHUB_PAT"); !sec.Variable {
		t.Fatal("second rollback lost the variable kind")
	}
}

func TestTokenSources(t *testing.T) {
	src, err := ParseSources("10.1.2.8, 10.1.3.0/24 ::ffff:10.9.9.9\n10.1.2.8 fd00::1")
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"10.1.2.8/32", "10.1.3.0/24", "10.9.9.9/32", "fd00::1/128"}
	if strings.Join(src, " ") != strings.Join(want, " ") {
		t.Fatalf("ParseSources = %v", src)
	}
	for _, bad := range []string{"10.1.2", "host.lan", "10.0.0.0/33", "fe80::1%eth0"} {
		if _, err := ParseSources(bad); err != ErrBadSource {
			t.Errorf("ParseSources(%q) accepted", bad)
		}
	}
	if got, _ := ParseSources(" , "); len(got) != 0 {
		t.Fatalf("empty list: %v", got)
	}

	s, _ := Open(t.TempDir(), key32())
	tok, _ := s.CreateToken("box", []string{"lab"}, false, []string{"10.1.2.8/32", "10.1.3.0/24"})
	for ip, ok := range map[string]bool{"10.1.2.8": true, "10.1.3.200": true, "::ffff:10.1.2.8": true, "10.1.2.9": false, "garbage": false, "": false} {
		_, err := s.LookupToken(tok, ip)
		if (err == nil) != ok {
			t.Errorf("from %q: err=%v, want allowed=%v", ip, err, ok)
		}
	}
	if got, err := s.LookupToken(tok, "10.9.9.9"); err != ErrSource || got.Name != "box" {
		t.Fatalf("denied lookup should name the token: %+v %v", got, err)
	}
	if tk := s.ListTokens()[0]; tk.LastUsedFrom == "10.9.9.9" {
		t.Fatal("denied use recorded as last use")
	}
	s.SetTokenSources("box", nil)
	if _, err := s.LookupToken(tok, "192.168.1.1"); err != nil {
		t.Fatal("no sources should mean anywhere")
	}
	if err := s.SetTokenSources("box", []string{"nope"}); err != ErrBadSource {
		t.Fatal("bad source stored")
	}
}
