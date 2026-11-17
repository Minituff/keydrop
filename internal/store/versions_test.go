package store

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// olderPlain decrypts a key's older values, newest first, with their kinds.
func olderPlain(t *testing.T, s *Store, ns, name string) []string {
	t.Helper()
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []string
	for _, o := range s.st.Secrets[key(ns, name)].olderValues() {
		pt, err := s.open(o.Value, aad(ns, name, o.field))
		if err != nil {
			t.Fatalf("older value %s: %v", o.ID, err)
		}
		kind := "s"
		if o.Variable {
			kind = "v"
		}
		out = append(out, string(pt)+"/"+kind)
	}
	return out
}

func current(t *testing.T, s *Store, ns, name string) string {
	t.Helper()
	v, variable, err := s.Reveal(ns, name, "test")
	must(t, err)
	if variable {
		return string(v) + "/v"
	}
	return string(v) + "/s"
}

func stateJSON(s *Store) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	b, _ := json.Marshal(&s.st)
	return string(b)
}

// historyStore has lab/K saved seven times, v1 to v7: by the admin, by a
// write token (v2, v5) and as a variable (v3), a minute apart.
func historyStore(t *testing.T, dir string) (*Store, time.Time) {
	t.Helper()
	s, err := Open(dir, key32())
	must(t, err)
	t0 := time.Date(2026, 11, 1, 10, 0, 0, 0, time.UTC)
	clock := t0
	s.SetClock(func() time.Time { return clock })
	_, err = s.CreateToken("writer", []string{"lab"}, PermWrite, nil)
	must(t, err)
	tok := *s.st.Tokens["writer"]
	for i := 1; i <= 7; i++ {
		v := []byte(fmt.Sprintf("v%d", i))
		switch i {
		case 2, 5:
			_, err = s.AgentPut("lab", "K", v, AgentPut{Token: tok, Overwrite: true})
		default:
			err = s.SetValue("lab", "K", v, i == 3)
		}
		must(t, err)
		clock = clock.Add(time.Minute)
	}
	return s, t0
}

func TestVersionHistoryFillsAndDrops(t *testing.T) {
	s, t0 := historyStore(t, t.TempDir())
	if got := current(t, s, "lab", "K"); got != "v7/s" {
		t.Fatalf("current %s", got)
	}
	if got := strings.Join(olderPlain(t, s, "lab", "K"), " "); got != "v6/s v5/s v4/s v3/v v2/s" {
		t.Fatalf("older values: %s", got)
	}
	rows := s.Versions("lab", "K")
	if len(rows) != MaxVersions {
		t.Fatalf("%d rows", len(rows))
	}
	wantBy := []string{"admin", "token:writer", "admin", "admin", "token:writer"}
	for i, r := range rows {
		// v6 was replaced by v7's save, at minute 6; v2 at minute 2.
		at := t0.Add(time.Duration(6-i) * time.Minute)
		if r.Age != i+1 || r.By != wantBy[i] || !r.ReplacedAt.Equal(at) || r.Variable != (i == 3) || r.ID == "" {
			t.Fatalf("row %d: %+v, want by %s at %v", i, r, wantBy[i], at)
		}
	}
	// The history is kept outside the copies that leave the store.
	if sec, _ := s.GetSecret("lab", "K"); sec.Versions != nil {
		t.Fatal("GetSecret returns the history")
	}
	for _, sec := range s.ListSecrets(nil) {
		if sec.Versions != nil {
			t.Fatal("ListSecrets returns the history")
		}
	}
}

// A key's first value has no history, so the file has no mac7 until a
// value is replaced.
func TestFirstValueNoHistory(t *testing.T) {
	dir := t.TempDir()
	s, _ := Open(dir, key32())
	must(t, s.PutValue("lab", "ONE", []byte("only-value"), nil))
	must(t, s.Request("lab", "REQ", "", "", "agent"))
	must(t, s.SetValue("lab", "REQ", []byte("filled"), false))
	data, _ := os.ReadFile(filepath.Join(dir, stateFile))
	if bytes.Contains(data, []byte(`"versions"`)) || bytes.Contains(data, []byte(`"mac7"`)) {
		t.Fatal("history written for a first value")
	}
	if len(s.Versions("lab", "ONE")) != 0 {
		t.Fatal("rows for a first value")
	}
	must(t, s.PutValue("lab", "ONE", []byte("second"), nil))
	if rows := s.Versions("lab", "ONE"); len(rows) != 1 || rows[0].By != "admin" {
		t.Fatalf("saved by of a first value, from the change log: %+v", rows)
	}
}

func TestRestoreAnyVersion(t *testing.T) {
	dir := t.TempDir()
	s, _ := historyStore(t, dir)
	rows := s.Versions("lab", "K")
	// Older value 3 (v4) becomes current; v7 goes in front; nothing lost.
	v, of, err := s.Restore("lab", "K", rows[2].ID)
	must(t, err)
	if v.Age != 3 || of != 5 || v.ID != rows[2].ID {
		t.Fatalf("restored %+v of %d", v, of)
	}
	if got := current(t, s, "lab", "K"); got != "v4/s" {
		t.Fatalf("current %s", got)
	}
	if got := strings.Join(olderPlain(t, s, "lab", "K"), " "); got != "v7/s v6/s v5/s v3/v v2/s" {
		t.Fatalf("older values: %s", got)
	}
	after := s.Versions("lab", "K")
	// IDs stay with their values, so a page out of date can't restore
	// another one; v7 got a new one.
	if after[1].ID != rows[0].ID || after[3].ID != rows[3].ID || after[0].ID == rows[2].ID || after[0].By != "admin" {
		t.Fatalf("ids after restore: %+v", after)
	}
	// The variable (v3) comes back as a variable, saved by the admin.
	_, _, err = s.Restore("lab", "K", rows[3].ID)
	must(t, err)
	if got := current(t, s, "lab", "K"); got != "v3/v" {
		t.Fatalf("current %s", got)
	}
	if got := strings.Join(olderPlain(t, s, "lab", "K"), " "); got != "v4/s v7/s v6/s v5/s v2/s" {
		t.Fatalf("older values: %s", got)
	}
	// Rollback (the old route) is the newest: a swap, as before.
	must(t, s.Rollback("lab", "K"))
	if got := current(t, s, "lab", "K"); got != "v4/s" {
		t.Fatalf("current after rollback %s", got)
	}
	if got := strings.Join(olderPlain(t, s, "lab", "K"), " "); got != "v3/v v7/s v6/s v5/s v2/s" {
		t.Fatalf("older values: %s", got)
	}
	// The saver travels with the value: v5 was the agent's.
	_, _, err = s.Restore("lab", "K", s.Versions("lab", "K")[3].ID)
	must(t, err)
	if rows := s.Versions("lab", "K"); rows[0].By != "admin" || s.st.Secrets["lab/K"].Versions.By != "token:writer" {
		t.Fatalf("saved by after restoring the agent's value: %+v", rows[0])
	}
	// Everything survives a reopen.
	s2, err := Open(dir, key32())
	must(t, err)
	if got := strings.Join(olderPlain(t, s2, "lab", "K"), " "); got != "v4/s v3/v v7/s v6/s v2/s" {
		t.Fatalf("older values after reopening: %s", got)
	}
}

func TestRestoreUnknownChangesNothing(t *testing.T) {
	dir := t.TempDir()
	s, _ := historyStore(t, dir)
	before := stateJSON(s)
	file, _ := os.ReadFile(filepath.Join(dir, stateFile))
	for _, id := range []string{"0123456789abcdef", "previous", "../x"} {
		if _, _, err := s.Restore("lab", "K", id); !errors.Is(err, ErrNoVersion) {
			t.Fatalf("%q: %v", id, err)
		}
	}
	if _, _, err := s.Restore("lab", "NONE", ""); !errors.Is(err, ErrNotFound) {
		t.Fatal(err)
	}
	if stateJSON(s) != before {
		t.Fatal("a refused restore changed the state")
	}
	if after, _ := os.ReadFile(filepath.Join(dir, stateFile)); !bytes.Equal(after, file) {
		t.Fatal("a refused restore wrote the file")
	}
	must(t, s.PutValue("lab", "ONE", []byte("only"), nil))
	if err := s.Rollback("lab", "ONE"); !errors.Is(err, ErrNoPrevious) {
		t.Fatal(err)
	}
	if _, _, err := s.Restore("lab", "ONE", "0123456789abcdef"); !errors.Is(err, ErrNoVersion) {
		t.Fatal(err)
	}
}

// A failed save leaves the history as it was.
func TestVersionsFailedSave(t *testing.T) {
	dir := t.TempDir()
	s, _ := historyStore(t, dir)
	before := stateJSON(s)
	s.path = filepath.Join(dir, "missing", stateFile) // saves now fail
	if _, _, err := s.Restore("lab", "K", s.Versions("lab", "K")[2].ID); err == nil {
		t.Fatal("save didn't fail")
	}
	if err := s.PutValue("lab", "K", []byte("v8"), nil); err == nil {
		t.Fatal("save didn't fail")
	}
	if stateJSON(s) != before {
		t.Fatal("memory shows a change that wasn't saved")
	}
}

// Each older value is sealed to its key and its slot: moved anywhere
// else, it won't decrypt, and a restore fails without changing anything.
func TestVersionsBoundToSlot(t *testing.T) {
	try := func(name string, edit func(s *Store), restore func(s *Store) error) {
		t.Helper()
		s, _ := historyStore(t, t.TempDir())
		must(t, s.PutValue("lab", "OTHER", []byte("o1"), nil))
		must(t, s.PutValue("lab", "OTHER", []byte("o2"), nil))
		must(t, s.PutValue("lab", "OTHER", []byte("o3"), nil))
		s.mu.Lock()
		edit(s)
		s.mu.Unlock()
		before := stateJSON(s)
		if err := restore(s); err == nil {
			t.Fatalf("%s: restored", name)
		}
		if stateJSON(s) != before {
			t.Fatalf("%s: a failed restore changed the state", name)
		}
		if got := current(t, s, "lab", "K"); got != "v7/s" {
			t.Fatalf("%s: current %s", name, got)
		}
	}
	sec := func(s *Store, n string) *Secret { return s.st.Secrets["lab/"+n] }
	older := func(s *Store, n string) []Version { return sec(s, n).Versions.Older }
	id := func(i int) func(s *Store) error {
		return func(s *Store) error { _, _, err := s.Restore("lab", "K", s.Versions("lab", "K")[i].ID); return err }
	}
	try("two slots swapped", func(s *Store) {
		o := older(s, "K")
		o[0].Value, o[1].Value = o[1].Value, o[0].Value
	}, id(1))
	try("two slots swapped, the other one", func(s *Store) {
		o := older(s, "K")
		o[0].Value, o[1].Value = o[1].Value, o[0].Value
	}, id(2))
	try("from another key, same ID", func(s *Store) {
		older(s, "K")[0] = older(s, "OTHER")[0]
	}, id(1))
	try("previous and a slot swapped", func(s *Store) {
		o := older(s, "K")
		sec(s, "K").Previous, o[0].Value = o[0].Value, sec(s, "K").Previous
	}, id(0))
	try("previous and a slot swapped, the slot", func(s *Store) {
		o := older(s, "K")
		sec(s, "K").Previous, o[0].Value = o[0].Value, sec(s, "K").Previous
	}, id(1))
	try("the current value in a slot", func(s *Store) {
		older(s, "K")[0].Value = sec(s, "K").Value
	}, id(1))
	// A save moves Previous into a slot, so it fails too, rather than
	// dropping a value that won't decrypt.
	try("previous from another key, then a save", func(s *Store) {
		sec(s, "K").Previous = sec(s, "OTHER").Previous
	}, func(s *Store) error { return s.PutValue("lab", "K", []byte("v8"), nil) })
}

func TestDeleteClearsVersions(t *testing.T) {
	s, _ := historyStore(t, t.TempDir())
	must(t, s.Delete("lab", "K"))
	must(t, s.PutValue("lab", "K", []byte("fresh"), nil))
	if rows := s.Versions("lab", "K"); len(rows) != 0 {
		t.Fatalf("history after delete: %+v", rows)
	}
	if s.st.Secrets["lab/K"].Versions != nil || s.st.Secrets["lab/K"].Previous != nil {
		t.Fatal("history after delete")
	}
}

// The per-token storage cap counts the older values of the keys a token
// made, as it counts Previous; once the admin saves over a key it no longer
// counts, history included. (A token's own run of writes keeps only its
// newest older value, so another token's write is what makes a third.)
func TestTokenCapCountsVersions(t *testing.T) {
	s, tok := capStore(t)
	_, err := s.CreateToken("other", []string{"lab"}, PermWrite, nil)
	must(t, err)
	other := *s.st.Tokens["other"]
	size := MaxBytesPerToken/4 + 1
	put := func(tok Token) error {
		_, err := s.AgentPut("lab", "BIG", bytes.Repeat([]byte("x"), size), AgentPut{Token: tok, Overwrite: true})
		return err
	}
	must(t, put(tok))   // value
	must(t, put(tok))   // value and previous: 2 sizes
	must(t, put(other)) // its value, and bulk's newest: 2 sizes
	must(t, put(tok))   // value, previous and an older value: 3 sizes
	if got := len(s.Versions("lab", "BIG")); got != 2 {
		t.Fatalf("%d older values", got)
	}
	if err := put(tok); !errors.Is(err, ErrTokenCap) {
		t.Fatalf("fourth size: %v", err)
	}
	must(t, s.PutValue("lab", "BIG", []byte("admin"), nil))
	for i := 0; i < 4; i++ {
		must(t, put(tok)) // the admin's key now: not counted
	}
}

// A canary keeps its history, as it keeps Previous; and nothing about the
// history shows outside the store.
func TestCanaryKeepsVersions(t *testing.T) {
	s, _ := historyStore(t, t.TempDir())
	before := olderPlain(t, s, "lab", "K")
	must(t, s.SetCanary("lab", "K", true))
	must(t, s.SetCanary("lab", "K", false))
	if got := olderPlain(t, s, "lab", "K"); strings.Join(got, " ") != strings.Join(before, " ") {
		t.Fatalf("canary changed the history: %v", got)
	}
	// Restoring a variable over a canary unmarks it, like a rollback.
	must(t, s.SetCanary("lab", "K", true))
	_, _, err := s.Restore("lab", "K", s.Versions("lab", "K")[3].ID)
	must(t, err)
	if sec, _ := s.GetSecret("lab", "K"); sec.Canary || !sec.Variable {
		t.Fatalf("canary restored to a variable: %+v", sec)
	}
}

// clone copies the history deeply enough to undo a change.
func TestVersionsClone(t *testing.T) {
	s, _ := historyStore(t, t.TempDir())
	s.mu.Lock()
	snap := s.st.clone()
	s.mu.Unlock()
	was, _ := json.Marshal(snap.Secrets["lab/K"])
	_, _, err := s.Restore("lab", "K", s.Versions("lab", "K")[4].ID)
	must(t, err)
	must(t, s.PutValue("lab", "K", []byte("v8"), nil))
	if now, _ := json.Marshal(snap.Secrets["lab/K"]); string(now) != string(was) {
		t.Fatal("the snapshot changed with the state")
	}
}

// The history is under mac7, outside v6View. Editing it, or dropping it
// with mac7 kept, is refused; dropping both is what an older release
// writes: it opens with the current and previous values as they were.
func TestVersionsIntegrity(t *testing.T) {
	dir := t.TempDir()
	historyStore(t, dir)
	path := filepath.Join(dir, stateFile)
	data, _ := os.ReadFile(path)
	if !bytes.Contains(data, []byte(`"versions"`)) || !bytes.Contains(data, []byte(`"mac7"`)) {
		t.Fatal("no versions or mac7 in the file")
	}
	try := func(name string, edit func(raw map[string]any), want error) *Store {
		t.Helper()
		var raw map[string]any
		must(t, json.Unmarshal(data, &raw))
		edit(raw)
		b, _ := json.Marshal(raw)
		os.WriteFile(path, b, 0o600)
		s, err := Open(dir, key32())
		if !errors.Is(err, want) && !(want == nil && err == nil) {
			t.Fatalf("%s: %v, want %v", name, err, want)
		}
		return s
	}
	k := func(raw map[string]any) map[string]any {
		return raw["secrets"].(map[string]any)["lab/K"].(map[string]any)
	}
	vers := func(raw map[string]any) map[string]any { return k(raw)["versions"].(map[string]any) }
	slot := func(raw map[string]any, i int) map[string]any {
		return vers(raw)["older"].([]any)[i].(map[string]any)
	}
	try("unchanged", func(map[string]any) {}, nil)
	try("a slot's kind changed", func(raw map[string]any) { slot(raw, 1)["variable"] = true }, ErrIntegrity)
	try("a slot's saver changed", func(raw map[string]any) { slot(raw, 0)["by"] = "admin" }, ErrIntegrity)
	try("a slot's ID changed", func(raw map[string]any) { slot(raw, 0)["id"] = "0123456789abcdef" }, ErrIntegrity)
	try("two slots swapped", func(raw map[string]any) {
		o := vers(raw)["older"].([]any)
		o[0], o[1] = o[1], o[0]
	}, ErrIntegrity)
	try("a slot dropped", func(raw map[string]any) {
		vers(raw)["older"] = vers(raw)["older"].([]any)[1:]
	}, ErrIntegrity)
	try("the current saver changed", func(raw map[string]any) { vers(raw)["by"] = "token:writer" }, ErrIntegrity)
	try("versions dropped, mac7 kept", func(raw map[string]any) { delete(k(raw), "versions") }, ErrIntegrity)
	try("mac7 dropped", func(raw map[string]any) { delete(raw, "mac7") }, ErrIntegrity)
	try("versions edited, mac7 dropped", func(raw map[string]any) {
		delete(raw, "mac7")
		slot(raw, 1)["variable"] = true
	}, ErrIntegrity)
	// Both dropped: only the history goes.
	s := try("both dropped", func(raw map[string]any) {
		delete(k(raw), "versions")
		delete(raw, "mac7")
	}, nil)
	if got := current(t, s, "lab", "K"); got != "v7/s" {
		t.Fatalf("both dropped: current %s", got)
	}
	if got := strings.Join(olderPlain(t, s, "lab", "K"), " "); got != "v6/s" {
		t.Fatalf("both dropped: older values %s", got)
	}
	if tok, ok := tokenNamedT(s, "writer"); !ok || tok.Permission() != PermWrite {
		t.Fatal("both dropped: the token changed")
	}
	must(t, s.Rollback("lab", "K"))
	if got := current(t, s, "lab", "K"); got != "v6/s" {
		t.Fatalf("both dropped, rolled back: %s", got)
	}
}

// The release with MAC6 (v0.1.3) opens a file with history: its MACs
// verify over what it parses. When it rolls back (or saves anything) it
// writes the whole file without the history, and this release opens that
// with the current and previous values as it left them and builds history
// up again from there.
func TestV6ReleaseReadsVersionsFile(t *testing.T) {
	dir := t.TempDir()
	s0 := canaried(t, dir)
	must(t, s0.SetAlertWebhook(testWebhook))
	_, err := s0.CreateToken("agent", []string{"ns"}, PermRead, nil)
	must(t, err)
	must(t, s0.SetTokenSelfUpgrade("agent", true))
	historyStore(t, dir)
	path := filepath.Join(dir, stateFile)
	data, _ := os.ReadFile(path)
	for _, f := range []string{`"versions"`, `"mac7"`, `"mac6"`, `"mac5"`, `"mac4"`, `"mac3"`, `"mac2"`} {
		if !bytes.Contains(data, []byte(f)) {
			t.Fatalf("no %s in the file", f)
		}
	}
	var st state
	must(t, json.Unmarshal(data, &st))
	v6 := mac6Release(st)
	k, _ := newStore(dir, key32())
	legacy, v2, v3, v4, v5 := v6.legacyView(), v6.v2View(), v6.v3View(), v6.v4View(), v6.v5View()
	if !hmacEqual(v6.MAC, macOf(k.macKey, &legacy)) || !hmacEqual(v6.MAC2, macOf(k.mac2Key, &v2)) ||
		!hmacEqual(v6.MAC3, macOf(k.mac3Key, &v3)) || !hmacEqual(v6.MAC4, macOf(k.mac4Key, &v4)) ||
		!hmacEqual(v6.MAC5, macOf(k.mac5Key, &v5)) || !checkMAC6(k, v6) {
		t.Fatal("the v6 release would refuse this file")
	}
	// What that release does on Roll back: swap value and previous, each
	// resealed for its field, and write the file it parsed.
	sec := v6.Secrets["lab/K"]
	cur, err := k.open(sec.Value, aad("lab", "K", "value"))
	must(t, err)
	prev, err := k.open(sec.Previous, aad("lab", "K", "previous"))
	must(t, err)
	sec.Value, sec.Previous = k.seal(prev, aad("lab", "K", "value")), k.seal(cur, aad("lab", "K", "previous"))
	sec.Variable, sec.PreviousVariable = sec.PreviousVariable, sec.Variable
	k.st = v6
	must(t, k.write(true, false)) // what it writes: the canaries made MAC4 required
	data, _ = os.ReadFile(path)
	if bytes.Contains(data, []byte(`"versions"`)) || bytes.Contains(data, []byte(`"mac7"`)) {
		t.Fatal("the v6 release's file has history")
	}
	s, err := Open(dir, key32())
	if err != nil {
		t.Fatalf("open after the v6 release wrote it: %v", err)
	}
	if got := current(t, s, "lab", "K"); got != "v6/s" {
		t.Fatalf("current %s", got)
	}
	if got := strings.Join(olderPlain(t, s, "lab", "K"), " "); got != "v7/s" {
		t.Fatalf("older values %s", got)
	}
	if rows := s.Versions("lab", "K"); len(rows) != 1 || rows[0].By != "" || !rows[0].ReplacedAt.IsZero() {
		t.Fatalf("what's known of a previous value the v6 release wrote: %+v", rows)
	}
	// Restoring by the ID the page showed works, and new saves build up
	// history again.
	_, _, err = s.Restore("lab", "K", s.Versions("lab", "K")[0].ID)
	must(t, err)
	must(t, s.PutValue("lab", "K", []byte("v8"), nil))
	if got := strings.Join(olderPlain(t, s, "lab", "K"), " "); got != "v7/s v6/s" {
		t.Fatalf("older values after new saves %s", got)
	}
}

// A value a token saves stores its saver, even as a key's first value, so
// ValueAuthor names it for as long as it's current, however much of the
// change log is trimmed; a restore brings an older value's saver back with
// it, and the admin's save takes the label away.
func TestValueAuthorStored(t *testing.T) {
	dir := t.TempDir()
	s, err := Open(dir, key32())
	must(t, err)
	_, err = s.CreateToken("writer", []string{"lab"}, PermWrite, nil)
	must(t, err)
	tok := *s.st.Tokens["writer"]
	put := func(name, v string) {
		t.Helper()
		_, err := s.AgentPut("lab", name, []byte(v), AgentPut{Token: tok, Overwrite: true, Variable: true})
		must(t, err)
	}
	must(t, s.PutValue("lab", "ADMIN_VAR", []byte("admin-text"), &Meta{Variable: true}))
	put("ADMIN_VAR", "agent-text") // over the admin's variable
	put("FIRST", "agent-first")    // a key's first value
	for _, n := range []string{"ADMIN_VAR", "FIRST"} {
		if sec := s.st.Secrets[key("lab", n)]; sec.Versions == nil || sec.Versions.By != "token:writer" {
			t.Fatalf("%s: saver not stored: %+v", n, sec.Versions)
		}
	}
	for i := range 600 { // more events than a namespace keeps
		put("SCRATCH", fmt.Sprintf("scratch-%d", i))
	}
	if n := len(s.History(func(ev Event) bool { return ev.Name == "ADMIN_VAR" || ev.Name == "FIRST" }, 0)); n != 1 {
		t.Fatalf("%d events left for the agent's keys, want only the admin's", n)
	}
	for _, n := range []string{"ADMIN_VAR", "FIRST"} {
		if by := s.ValueAuthor("lab", n); by != "writer" {
			t.Fatalf("%s after its events aged out: %q", n, by)
		}
	}
	// Reopened: what's stored, not what's in memory.
	s, err = Open(dir, key32())
	must(t, err)
	if by := s.ValueAuthor("lab", "ADMIN_VAR"); by != "writer" {
		t.Fatalf("reopened: %q", by)
	}
	must(t, s.SetValue("lab", "ADMIN_VAR", []byte("admin-again"), true))
	if by := s.ValueAuthor("lab", "ADMIN_VAR"); by != "" {
		t.Fatalf("after the admin's save: %q", by)
	}
	rows := s.Versions("lab", "ADMIN_VAR")
	_, _, err = s.Restore("lab", "ADMIN_VAR", rows[0].ID) // the agent's
	must(t, err)
	if by := s.ValueAuthor("lab", "ADMIN_VAR"); by != "writer" {
		t.Fatalf("after restoring the agent's value: %q", by)
	}
	must(t, s.Rollback("lab", "ADMIN_VAR")) // the admin's again
	if by := s.ValueAuthor("lab", "ADMIN_VAR"); by != "" {
		t.Fatalf("after restoring the admin's value: %q", by)
	}
	// The admin's own first value stores nothing new (see
	// TestFirstValueNoHistory) and reads as the admin's.
	must(t, s.PutValue("lab", "PLAIN", []byte("x"), &Meta{Variable: true}))
	if s.st.Secrets[key("lab", "PLAIN")].Versions != nil || s.ValueAuthor("lab", "PLAIN") != "" {
		t.Fatal("the admin's first value")
	}
}

// The stored saver is under MAC7 like the rest of the history: it can't be
// edited or dropped without the master key. Dropping it together with
// MAC7 (what the release with MAC6 writes back, on a file with no per-key
// limit) leaves the label to the change log, as before this release.
func TestValueAuthorIntegrity(t *testing.T) {
	dir := t.TempDir()
	s, err := Open(dir, key32())
	must(t, err)
	_, err = s.CreateToken("writer", []string{"lab"}, PermWrite, nil)
	must(t, err)
	tok := *s.st.Tokens["writer"]
	_, err = s.AgentPut("lab", "URL", []byte("agent-text"), AgentPut{Token: tok, Variable: true})
	must(t, err)
	path := filepath.Join(dir, stateFile)
	data, _ := os.ReadFile(path)
	if !bytes.Contains(data, []byte(`"versions"`)) || !bytes.Contains(data, []byte(`"mac7"`)) {
		t.Fatal("no stored saver or mac7 in the file")
	}
	try := func(name string, edit func(raw map[string]any), want error) *Store {
		t.Helper()
		var raw map[string]any
		must(t, json.Unmarshal(data, &raw))
		edit(raw)
		b, _ := json.Marshal(raw)
		os.WriteFile(path, b, 0o600)
		s, err := Open(dir, key32())
		if !errors.Is(err, want) && !(want == nil && err == nil) {
			t.Fatalf("%s: %v, want %v", name, err, want)
		}
		return s
	}
	sec := func(raw map[string]any) map[string]any {
		return raw["secrets"].(map[string]any)["lab/URL"].(map[string]any)
	}
	try("saver made the admin", func(raw map[string]any) {
		sec(raw)["versions"].(map[string]any)["by"] = "admin"
	}, ErrIntegrity)
	try("saver dropped, mac7 kept", func(raw map[string]any) { delete(sec(raw), "versions") }, ErrIntegrity)
	try("mac7 dropped", func(raw map[string]any) { delete(raw, "mac7") }, ErrIntegrity)
	s = try("both dropped", stripV7, nil)
	if by := s.ValueAuthor("lab", "URL"); by != "writer" {
		t.Fatalf("both dropped, the log still has the event: %q", by)
	}
}

// The release with MAC6 (v0.1.3) opens a file with stored savers and,
// writing it back, drops them. The label then comes from the change log
// again, which is that release's behaviour: kept while the token's event
// is in the log, gone once the token has written enough to age it out
// (the residual the design doc names). Saving again stores it again.
func TestValueAuthorAfterV6Release(t *testing.T) {
	dir := t.TempDir()
	s := canaried(t, dir)
	_, err := s.CreateToken("agent", []string{"ns"}, PermRead, nil)
	must(t, err)
	must(t, s.SetTokenSelfUpgrade("agent", true)) // so the file has a mac6
	_, err = s.CreateToken("writer", []string{"lab"}, PermWrite, nil)
	must(t, err)
	tok := *s.st.Tokens["writer"]
	must(t, s.PutValue("lab", "URL", []byte("admin-text"), &Meta{Variable: true}))
	_, err = s.AgentPut("lab", "URL", []byte("agent-text"), AgentPut{Token: tok, Variable: true, Overwrite: true})
	must(t, err)
	data, _ := os.ReadFile(filepath.Join(dir, stateFile))
	var st state
	must(t, json.Unmarshal(data, &st))
	k, _ := newStore(dir, key32())
	if !checkMAC6(k, mac6Release(st)) {
		t.Fatal("the v6 release would refuse this file")
	}
	asV6Wrote(t, s)
	s, err = Open(dir, key32())
	must(t, err)
	if s.st.Secrets[key("lab", "URL")].Versions != nil {
		t.Fatal("the v6 release's file has a stored saver")
	}
	if by := s.ValueAuthor("lab", "URL"); by != "writer" {
		t.Fatalf("from the change log: %q", by)
	}
	for i := range 600 {
		_, err := s.AgentPut("lab", "SCRATCH", []byte(fmt.Sprintf("scratch-%d", i)), AgentPut{Token: tok, Overwrite: true})
		must(t, err)
	}
	if by := s.ValueAuthor("lab", "URL"); by != "" {
		t.Fatalf("the residual changed: %q (update the design doc)", by)
	}
	_, err = s.AgentPut("lab", "URL", []byte("agent-again"), AgentPut{Token: tok, Variable: true, Overwrite: true})
	must(t, err)
	if by := s.ValueAuthor("lab", "URL"); by != "writer" || s.st.Secrets[key("lab", "URL")].Versions.By != "token:writer" {
		t.Fatalf("saved again: %q", by)
	}
}

// When an agent saves, the history keeps only each agent's newest older
// value: a run of writes by one token can't push the admin's older values
// out, and holds at most two of its values on the key (current and one
// older), whatever their size. Two tokens alternating take two slots.
func TestAgentWritesKeepAdminHistory(t *testing.T) {
	s, err := Open(t.TempDir(), key32())
	must(t, err)
	_, err = s.CreateToken("t1", []string{"lab"}, PermWrite, nil)
	must(t, err)
	t1 := *s.st.Tokens["t1"]
	big := strings.Repeat("x", 4000)
	put := func(tok Token, name, v string) {
		t.Helper()
		_, err := s.AgentPut("lab", name, []byte(v), AgentPut{Token: tok, Overwrite: true})
		must(t, err)
	}
	for _, v := range []string{"A", "B", "C"} {
		must(t, s.SetValue("lab", "K", []byte(v), false))
	}
	for _, v := range []string{"A", "B", "C"} {
		must(t, s.SetValue("lab", "DECOY", []byte(v), false))
	}
	must(t, s.SetCanary("lab", "DECOY", true))
	for i := range 10 {
		put(t1, "K", fmt.Sprintf("w%d-%s", i, big))
		put(t1, "DECOY", fmt.Sprintf("w%d-%s", i, big))
	}
	short := func(name string) string {
		var out []string
		for _, v := range olderPlain(t, s, "lab", name) {
			out = append(out, strings.TrimSuffix(strings.TrimSuffix(v, "/s"), "-"+big))
		}
		return strings.Join(out, " ")
	}
	if got := short("K"); got != "w8 C B A" {
		t.Fatalf("after ten writes by one token: %s", got)
	}
	// A canary's history works the same: agents can't tell one by it.
	if got := short("DECOY"); got != "w8 C B A" {
		t.Fatalf("canary, after ten writes: %s", got)
	}
	if sec := s.st.Secrets[key("lab", "K")]; len(sec.Value)+len(sec.Previous)+sec.olderBytes() > 2*(len(big)+100)+3*100 {
		t.Fatalf("%d bytes held on the key", len(sec.Value)+len(sec.Previous)+sec.olderBytes())
	}
	// Every row left restores, by its ID.
	byID := map[string]string{}
	for i, r := range s.Versions("lab", "K") {
		byID[r.ID] = olderPlain(t, s, "lab", "K")[i]
	}
	for id, want := range byID {
		_, _, err := s.Restore("lab", "K", id)
		must(t, err)
		if got := current(t, s, "lab", "K"); got != want {
			t.Fatalf("restored %s: %.10s, want %.10s", id, got, want)
		}
	}
	// The admin's own saves keep five, agents' values included.
	s2, err := Open(t.TempDir(), key32())
	must(t, err)
	_, err = s2.CreateToken("t1", []string{"lab"}, PermWrite, nil)
	must(t, err)
	_, err = s2.AgentPut("lab", "K", []byte("w0"), AgentPut{Token: *s2.st.Tokens["t1"]})
	must(t, err)
	_, err = s2.AgentPut("lab", "K", []byte("w1"), AgentPut{Token: *s2.st.Tokens["t1"], Overwrite: true})
	must(t, err)
	for _, v := range []string{"A", "B", "C", "D"} {
		must(t, s2.SetValue("lab", "K", []byte(v), false))
	}
	if got := strings.Join(olderPlain(t, s2, "lab", "K"), " "); got != "C/s B/s A/s w1/s w0/s" {
		t.Fatalf("the admin's saves: %s", got)
	}
	// Two tokens alternating keep one older value each: of the admin's
	// four values, the newest three stay.
	s3, err := Open(t.TempDir(), key32())
	must(t, err)
	for _, n := range []string{"t1", "t2"} {
		_, err = s3.CreateToken(n, []string{"lab"}, PermWrite, nil)
		must(t, err)
	}
	for _, v := range []string{"A", "B", "C", "D"} {
		must(t, s3.SetValue("lab", "K", []byte(v), false))
	}
	for i := range 10 {
		for _, n := range []string{"t1", "t2"} {
			_, err := s3.AgentPut("lab", "K", []byte(fmt.Sprintf("%s-%d", n, i)), AgentPut{Token: *s3.st.Tokens[n], Overwrite: true})
			must(t, err)
		}
	}
	if got := strings.Join(olderPlain(t, s3, "lab", "K"), " "); got != "t1-9/s t2-8/s D/s C/s B/s" {
		t.Fatalf("two tokens: %s", got)
	}
}
