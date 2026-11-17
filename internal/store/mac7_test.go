package store

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// mac6Release is the state as the release with MAC6 (v0.1.3) parses a file
// this one wrote, with the MACs it reads, and checkMAC6 is what that release
// computes for its MAC6: the whole of what it parsed, MACs empty. Its state
// has no MAC7 and nothing after it, all omitempty, so a state with those
// unset marshals byte-for-byte as its own does.
func mac6Release(st state) state {
	c := st.v6View()
	c.MAC, c.MAC2, c.MAC3, c.MAC4, c.MAC5, c.MAC6 = st.MAC, st.MAC2, st.MAC3, st.MAC4, st.MAC5, st.MAC6
	return c
}

func checkMAC6(k *Store, v6 state) bool {
	check := v6
	check.MAC, check.MAC2, check.MAC3, check.MAC4, check.MAC5, check.MAC6 = nil, nil, nil, nil, nil, nil
	return hmacEqual(v6.MAC6, macOf(k.mac6Key, &check))
}

// A file with everything up to MAC6 in use, and nothing after it, is what
// the release with MAC6 writes: it has no mac7, its mac6 is the one that
// release computes, and it opens here unchanged.
func TestMAC6FileOpens(t *testing.T) {
	dir := t.TempDir()
	s := canaried(t, dir)
	must(t, s.SetAlertWebhook(testWebhook))
	_, err := s.CreateToken("agent", []string{"ns"}, PermRead, nil)
	must(t, err)
	must(t, s.SetTokenSelfUpgrade("agent", true))
	path := filepath.Join(dir, stateFile)
	data, _ := os.ReadFile(path)
	if strings.Contains(string(data), `"mac7"`) {
		t.Fatal("mac7 with nothing after MAC6 set")
	}
	var st state
	must(t, json.Unmarshal(data, &st))
	k, _ := newStore(dir, key32())
	if !checkMAC6(k, mac6Release(st)) {
		t.Fatal("mac6 isn't what the release with MAC6 computes")
	}
	if _, err := Open(dir, key32()); err != nil {
		t.Fatalf("open: %v", err)
	}
	if after, _ := os.ReadFile(path); string(after) != string(data) {
		t.Fatal("opening the file changed it")
	}
}

// A mac7 that's present must verify, even with nothing after MAC6 set.
func TestMAC7Integrity(t *testing.T) {
	dir := t.TempDir()
	canaried(t, dir)
	path := filepath.Join(dir, stateFile)
	data, _ := os.ReadFile(path)
	k, _ := newStore(dir, key32())
	try := func(name string, mac7 func(st state) []byte, want error) {
		t.Helper()
		var raw map[string]any
		must(t, json.Unmarshal(data, &raw))
		var st state
		must(t, json.Unmarshal(data, &st))
		raw["mac7"] = mac7(st)
		b, _ := json.Marshal(raw)
		os.WriteFile(path, b, 0o600)
		_, err := Open(dir, key32())
		if !errors.Is(err, want) && !(want == nil && err == nil) {
			t.Fatalf("%s: %v, want %v", name, err, want)
		}
	}
	try("mac7 wrong", func(state) []byte { return make([]byte, 32) }, ErrIntegrity)
	try("mac7 under another key", func(st state) []byte {
		c := st
		c.MAC, c.MAC2, c.MAC3, c.MAC4, c.MAC5, c.MAC6 = nil, nil, nil, nil, nil, nil
		return macOf(k.mac6Key, &c)
	}, ErrIntegrity)
	try("mac7 right", func(st state) []byte {
		c := st
		c.MAC, c.MAC2, c.MAC3, c.MAC4, c.MAC5, c.MAC6 = nil, nil, nil, nil, nil, nil
		return macOf(k.mac7Key, &c)
	}, nil)
}

// The views as they were before v6View copied the secrets (bb993bf), for
// TestViewsUnchangedBySecretCopies.
func oldViews(st *state) (legacy, v2, v3, v4, v5, v6 state) {
	v6 = *st
	v6.MAC, v6.MAC2, v6.MAC3, v6.MAC4, v6.MAC5, v6.MAC6, v6.MAC7 = nil, nil, nil, nil, nil, nil, nil
	v6.Notify = nil
	v5 = v6
	v5.Tokens = map[string]*Token{}
	for k, v := range v6.Tokens {
		cp := *v
		cp.SelfUpgrade = false
		v5.Tokens[k] = &cp
	}
	v4 = v5
	v4.MAC5, v4.Alerts = nil, nil
	v3 = v4
	v3.MAC4, v3.Canary = nil, nil
	v3.Secrets = map[string]*Secret{}
	for k, v := range st.Secrets {
		cp := *v
		cp.Canary = false
		v3.Secrets[k] = &cp
	}
	v3.Tokens = map[string]*Token{}
	for k, v := range v4.Tokens {
		cp := *v
		cp.ExpiresAt, cp.Lifetime, cp.Renewal, cp.Rotation = nil, 0, nil, nil
		v3.Tokens[k] = &cp
	}
	// The older views wrote through v3's copies; copy again so v3 stays.
	cpSecrets := func(m map[string]*Secret, f func(*Secret)) map[string]*Secret {
		out := map[string]*Secret{}
		for k, v := range m {
			cp := *v
			f(&cp)
			out[k] = &cp
		}
		return out
	}
	v2 = v3
	v2.Groups, v2.Settings = nil, nil
	v2.Secrets = cpSecrets(v3.Secrets, func(s *Secret) { s.Group, s.Batch = "", nil })
	legacy = v2
	legacy.History, legacy.Fixups = nil, 0
	legacy.Secrets = cpSecrets(v2.Secrets, func(s *Secret) { s.Ext = nil })
	legacy.Tokens = map[string]*Token{}
	for k, v := range v2.Tokens {
		cp := *v
		cp.Add = false
		legacy.Tokens[k] = &cp
	}
	return
}

// v6View copies the secrets so a per-secret field can be zeroed in it.
// That changes nothing a MAC covers: every view marshals byte-for-byte as
// before, so every older release still verifies the file, and computing
// the views leaves the state alone.
func TestViewsUnchangedBySecretCopies(t *testing.T) {
	dir := t.TempDir()
	s := canaried(t, dir)
	must(t, s.SetAlertWebhook(testWebhook))
	_, err := s.CreateToken("agent", []string{"ns"}, PermRead, nil)
	must(t, err)
	must(t, s.SetTokenSelfUpgrade("agent", true))
	on := true
	must(t, s.SetInboxAlerts(&on))
	for name, st := range map[string]*state{"in use": &s.st, "empty": {}, "no secrets": {Tokens: s.st.Tokens}} {
		before, _ := json.Marshal(st)
		legacy, v2, v3, v4, v5, v6 := oldViews(st)
		for _, c := range []struct {
			view     string
			old, now state
		}{
			{"legacy", legacy, st.legacyView()}, {"v2", v2, st.v2View()}, {"v3", v3, st.v3View()},
			{"v4", v4, st.v4View()}, {"v5", v5, st.v5View()}, {"v6", v6, st.v6View()},
		} {
			o, _ := json.Marshal(&c.old)
			n, _ := json.Marshal(&c.now)
			if string(o) != string(n) {
				t.Fatalf("%s: %s changed:\n%s\n%s", name, c.view, o, n)
			}
		}
		if after, _ := json.Marshal(st); string(after) != string(before) {
			t.Fatalf("%s: computing the views changed the state", name)
		}
	}
	// And the file's MACs still verify.
	if _, err := Open(dir, key32()); err != nil {
		t.Fatal(err)
	}
}
