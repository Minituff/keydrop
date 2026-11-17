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
