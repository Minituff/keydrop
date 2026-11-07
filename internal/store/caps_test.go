package store

import (
	"bytes"
	"errors"
	"fmt"
	"strings"
	"testing"
)

func capStore(t *testing.T) (*Store, Token) {
	t.Helper()
	s, err := Open(t.TempDir(), bytes.Repeat([]byte{1}, 32))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.CreateToken("bulk", []string{"lab"}, PermWrite, nil); err != nil {
		t.Fatal(err)
	}
	return s, *s.st.Tokens["bulk"]
}

func TestTokenKeyCap(t *testing.T) {
	s, tok := capStore(t)
	for i := 0; i < MaxKeysPerToken; i++ {
		if _, err := s.AgentPut("lab", fmt.Sprintf("K_%d", i), []byte("v"), AgentPut{Token: tok}); err != nil {
			t.Fatalf("key %d: %v", i, err)
		}
	}
	if _, err := s.AgentPut("lab", "ONE_MORE", []byte("v"), AgentPut{Token: tok}); !errors.Is(err, ErrTokenCap) {
		t.Fatalf("over the cap: %v", err)
	}
	if _, ok := s.GetSecret("lab", "ONE_MORE"); ok {
		t.Fatal("a refused put left a key behind")
	}
	// At the cap it can still replace what it has...
	if _, err := s.AgentPut("lab", "K_0", []byte("v2"), AgentPut{Token: tok, Overwrite: true}); err != nil {
		t.Fatalf("replacing at the cap: %v", err)
	}
	// ...and a key the admin takes over stops counting.
	must(t, s.PutValue("lab", "K_1", []byte("admin"), nil))
	if _, err := s.AgentPut("lab", "ONE_MORE", []byte("v"), AgentPut{Token: tok}); err != nil {
		t.Fatalf("after the admin took one over: %v", err)
	}
}

func TestTokenByteCap(t *testing.T) {
	s, tok := capStore(t)
	big := []byte(strings.Repeat("k", 1<<20))
	var err error
	n := 0
	for ; n < 20 && err == nil; n++ {
		_, err = s.AgentPut("lab", fmt.Sprintf("B_%d", n), big, AgentPut{Token: tok})
	}
	if !errors.Is(err, ErrTokenCap) {
		t.Fatalf("no byte cap after %d MiB: %v", n, err)
	}
	if n > MaxBytesPerToken>>20+1 {
		t.Fatalf("cap reached only after %d MiB", n)
	}
	// Replacing its own keys counts too, or one key could grow past it.
	if _, err := s.AgentPut("lab", "B_0", big, AgentPut{Token: tok, Overwrite: true}); !errors.Is(err, ErrTokenCap) {
		t.Fatalf("replacing past the cap: %v", err)
	}
}

// The cap covers what a token made, so another token's keys don't use it.
func TestTokenCapIsPerToken(t *testing.T) {
	s, tok := capStore(t)
	must(t, s.PutValue("lab", "ADMIN_KEY", bytes.Repeat([]byte("k"), MaxBytesPerToken+1), nil))
	if _, err := s.AgentPut("lab", "SMALL", []byte("v"), AgentPut{Token: tok}); err != nil {
		t.Fatal(err)
	}
}

func TestAddressesOtherThan(t *testing.T) {
	s, tok := capStore(t)
	s.mu.Lock()
	s.noteAddress(tok.Name, "10.0.0.5")
	for i := 0; i < 20; i++ {
		s.noteAddress(tok.Name, fmt.Sprintf("10.0.1.%d", i))
	}
	s.noteAddress(tok.Name, "")
	n := len(s.recentFrom[tok.Name])
	s.mu.Unlock()
	if n != maxRecentFrom {
		t.Fatalf("kept %d addresses", n)
	}
	got := s.AddressesOtherThan(tok.Name, "10.0.1.19")
	if len(got) != maxRecentFrom-1 {
		t.Fatalf("%v", got)
	}
	for _, a := range got {
		if a == "10.0.1.19" {
			t.Fatal("listed the address it was asked to leave out")
		}
	}
}

func TestUnseenCharactersRefused(t *testing.T) {
	for _, bad := range []string{"a\ufe0fb", "a\U000e0100b", "a\u3164b", "a\u115fb", "a\u034fb", "a\u202eb"} {
		if err := CheckAgentText(bad, ""); !errors.Is(err, ErrBadText) {
			t.Fatalf("%q: %v", bad, err)
		}
	}
	if got := AgentLine(" ok\u202e\x1b \U000e0100text "); got != "ok text" {
		t.Fatalf("%q", got)
	}
	if got := AgentLine(strings.Repeat("é", 500)); len(got) > maxAgentLine || strings.ContainsRune(got, 0xfffd) {
		t.Fatalf("%d %q", len(got), got)
	}
}

// Nothing due means no copy of the state on the unauthenticated poll path.
func TestSweepsWithNothingDue(t *testing.T) {
	s, _ := capStore(t)
	if got := s.RevokeUncollected(s.now()); got != nil {
		t.Fatal(got)
	}
	if got := s.RevokeUncollectedRotations(s.now()); got != nil {
		t.Fatal(got)
	}
}
