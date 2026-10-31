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
	v, err := s2.Reveal("lab", "CF", "test")
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
	if _, err := s.Reveal("b", "TWO", "x"); err == nil {
		t.Fatal("swapped ciphertext decrypted")
	}
}

func TestRollbackAndRequest(t *testing.T) {
	s, _ := Open(t.TempDir(), key32())
	if err := s.Request("lab", "GH", "need a PAT", "", "claude"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Reveal("lab", "GH", "x"); err != ErrNoValue {
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
	if v, _ := s.Reveal("lab", "GH", "x"); string(v) != "v1-value" {
		t.Fatalf("rollback gave %q", v)
	}
	s.Rollback("lab", "GH")
	if v, _ := s.Reveal("lab", "GH", "x"); string(v) != "v2-value" {
		t.Fatalf("roll forward gave %q", v)
	}
}

func TestTokens(t *testing.T) {
	dir := t.TempDir()
	s, _ := Open(dir, key32())
	tok, err := s.CreateToken("claude", []string{"lab"}, false)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := os.ReadFile(filepath.Join(dir, stateFile))
	if bytes.Contains(raw, []byte(tok)) {
		t.Fatal("token stored in plaintext")
	}
	got, ok := s.LookupToken(tok)
	if !ok || got.Name != "claude" || !got.Allows("lab") || got.Allows("wedding") {
		t.Fatalf("lookup: %+v %v", got, ok)
	}
	if _, ok := s.LookupToken(tok + "x"); ok {
		t.Fatal("wrong token accepted")
	}
	s.RevokeToken("claude")
	if _, ok := s.LookupToken(tok); ok {
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
