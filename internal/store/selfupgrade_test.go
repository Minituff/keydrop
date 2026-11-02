package store

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestTokenSelfUpgrade(t *testing.T) {
	dir := t.TempDir()
	s, err := Open(dir, key32())
	must(t, err)
	_, err = s.CreateToken("agent", []string{"ns"}, PermRead, nil)
	must(t, err)
	path := filepath.Join(dir, stateFile)
	if data, _ := os.ReadFile(path); strings.Contains(string(data), `"mac6"`) {
		t.Fatal("mac6 without self-upgrade on")
	}
	must(t, s.SetTokenSelfUpgrade("agent", true))
	if err := s.SetTokenSelfUpgrade("nobody", true); !errors.Is(err, ErrNotFound) {
		t.Fatalf("unknown token: %v", err)
	}
	s2, err := Open(dir, key32())
	must(t, err)
	if tok, _ := tokenNamedT(s2, "agent"); !tok.SelfUpgrade {
		t.Fatal("self-upgrade didn't survive reopening")
	}
	must(t, s2.SetTokenSelfUpgrade("agent", false))
	if data, _ := os.ReadFile(path); strings.Contains(string(data), `"mac6"`) || strings.Contains(string(data), `"self_upgrade"`) {
		t.Fatal("turning it off left it in the file")
	}
}

func tokenNamedT(s *Store, name string) (Token, bool) {
	for _, t := range s.ListTokens() {
		if t.Name == name {
			return t, true
		}
	}
	return Token{}, false
}

// The release with MAC5 opens a file with self-upgrade on (its MACs verify
// over what it parses), and what it writes back opens here, with
// self-upgrade off and everything else kept.
func TestV5ReleaseReadsSelfUpgradeFile(t *testing.T) {
	dir := t.TempDir()
	s := canaried(t, dir)
	must(t, s.SetAlertWebhook(testWebhook))
	_, err := s.CreateToken("agent", []string{"ns"}, PermRead, nil)
	must(t, err)
	must(t, s.SetTokenSelfUpgrade("agent", true))
	path := filepath.Join(dir, stateFile)
	data, _ := os.ReadFile(path)
	for _, f := range []string{`"self_upgrade"`, `"mac6"`, `"mac5"`, `"mac4"`} {
		if !strings.Contains(string(data), f) {
			t.Fatalf("no %s in the file", f)
		}
	}
	var st state
	must(t, json.Unmarshal(data, &st))
	// What the release with MAC5 parses: everything but self_upgrade and MAC6.
	v5 := st.v5View()
	v5.MAC, v5.MAC2, v5.MAC3, v5.MAC4, v5.MAC5 = st.MAC, st.MAC2, st.MAC3, st.MAC4, st.MAC5
	k, _ := newStore(dir, key32())
	legacy := v5.legacyView()
	if !hmacEqual(v5.MAC, macOf(k.macKey, &legacy)) {
		t.Fatal("mac would not verify in the v5 release")
	}
	v2 := v5.v2View()
	if !hmacEqual(v5.MAC2, macOf(k.mac2Key, &v2)) {
		t.Fatal("mac2 would not verify in the v5 release")
	}
	v3 := v5.v3View()
	if !hmacEqual(v5.MAC3, macOf(k.mac3Key, &v3)) {
		t.Fatal("mac3 would not verify in the v5 release")
	}
	v4 := v5.v4View()
	if !hmacEqual(v5.MAC4, macOf(k.mac4Key, &v4)) {
		t.Fatal("mac4 would not verify in the v5 release")
	}
	check := v5
	check.MAC, check.MAC2, check.MAC3, check.MAC4, check.MAC5 = nil, nil, nil, nil, nil
	if !hmacEqual(v5.MAC5, macOf(k.mac5Key, &check)) {
		t.Fatal("mac5 would not verify in the v5 release")
	}
	// The v5 release saves the same thing back.
	b, _ := json.MarshalIndent(&v5, "", "  ")
	os.WriteFile(path, b, 0o600)
	s2, err := Open(dir, key32())
	if err != nil {
		t.Fatalf("open after the v5 release wrote it: %v", err)
	}
	if tok, ok := tokenNamedT(s2, "agent"); !ok || tok.SelfUpgrade {
		t.Fatalf("after the v5 release rewrote it: %+v %v", tok, ok)
	}
	if u, _, _ := s2.AlertWebhook(); u != testWebhook {
		t.Fatal("the webhook was lost")
	}
}

// Self-upgrade is covered by MAC6.
func TestSelfUpgradeIntegrity(t *testing.T) {
	dir := t.TempDir()
	s := canaried(t, dir)
	_, err := s.CreateToken("agent", []string{"ns"}, PermRead, nil)
	must(t, err)
	_, err = s.CreateToken("other", []string{"ns"}, PermRead, nil)
	must(t, err)
	must(t, s.SetTokenSelfUpgrade("agent", true))
	path := filepath.Join(dir, stateFile)
	data, _ := os.ReadFile(path)
	try := func(name string, edit func(raw map[string]any), want error) {
		t.Helper()
		var raw map[string]any
		json.Unmarshal(data, &raw)
		edit(raw)
		b, _ := json.Marshal(raw)
		os.WriteFile(path, b, 0o600)
		_, err := Open(dir, key32())
		if !errors.Is(err, want) && !(want == nil && err == nil) {
			t.Fatalf("%s: %v, want %v", name, err, want)
		}
	}
	tok := func(raw map[string]any, n string) map[string]any {
		return raw["tokens"].(map[string]any)[n].(map[string]any)
	}
	try("unchanged", func(map[string]any) {}, nil)
	try("turned on for another agent", func(raw map[string]any) { tok(raw, "other")["self_upgrade"] = true }, ErrIntegrity)
	try("mac6 dropped", func(raw map[string]any) { delete(raw, "mac6") }, ErrIntegrity)
	try("turned off, mac6 kept", func(raw map[string]any) { delete(tok(raw, "agent"), "self_upgrade") }, ErrIntegrity)
	// Both dropped is what the release before writes: it opens, with
	// self-upgrade off.
	try("both dropped", func(raw map[string]any) { delete(tok(raw, "agent"), "self_upgrade"); delete(raw, "mac6") }, nil)
}
