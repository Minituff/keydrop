package store

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func key32() []byte { return bytes.Repeat([]byte{7}, 32) }

func TestRoundTripAndAtRest(t *testing.T) {
	dir := t.TempDir()
	s, err := Open(dir, key32())
	if err != nil {
		t.Fatal(err)
	}
	if err := s.PutValue("lab", "cf", []byte("super-secret-123"), &Meta{Description: "dns"}); err != nil {
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
	v, err := s2.Reveal("lab", "cf", "test")
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
	s.PutValue("a", "one", []byte("value-one"), nil)
	s.PutValue("b", "two", []byte("value-two"), nil)
	s.mu.Lock()
	s.st.Secrets["b/two"].Value = s.st.Secrets["a/one"].Value
	s.mu.Unlock()
	if _, err := s.Reveal("b", "two", "x"); err == nil {
		t.Fatal("swapped ciphertext decrypted")
	}
}

func TestRollbackAndRequest(t *testing.T) {
	s, _ := Open(t.TempDir(), key32())
	if err := s.Request("lab", "gh", "need a PAT", "", "claude"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Reveal("lab", "gh", "x"); err != ErrNoValue {
		t.Fatalf("want ErrNoValue, got %v", err)
	}
	s.PutValue("lab", "gh", []byte("v1-value"), nil)
	if sec, _ := s.GetSecret("lab", "gh"); sec.Pending || sec.Description != "need a PAT" || !sec.New {
		t.Fatalf("after fill: %+v", sec)
	}
	if err := s.Request("lab", "gh", "again", "", "claude"); err != ErrExists {
		t.Fatalf("re-request of filled secret: %v", err)
	}
	s.PutValue("lab", "gh", []byte("v2-value"), nil)
	s.Rollback("lab", "gh")
	if v, _ := s.Reveal("lab", "gh", "x"); string(v) != "v1-value" {
		t.Fatalf("rollback gave %q", v)
	}
	s.Rollback("lab", "gh")
	if v, _ := s.Reveal("lab", "gh", "x"); string(v) != "v2-value" {
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
}
