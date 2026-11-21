package store

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// limited is canaried (every field up to MAC4 in use) with two read tokens
// in lab, lab/CF limited to "one" and lab/NOBODY limited to no token.
func limited(t *testing.T, dir string) *Store {
	t.Helper()
	s := canaried(t, dir)
	for _, n := range []string{"one", "two"} {
		if _, err := s.CreateToken(n, []string{"lab"}, PermRead, nil); err != nil {
			t.Fatal(err)
		}
	}
	must(t, s.SetAlertWebhook(testWebhook))
	must(t, s.SetTokenSelfUpgrade("two", true))
	must(t, s.PutValue("lab", "NOBODY", []byte("nobody-value"), nil))
	must(t, s.SetLimit("lab", "CF", true, []string{"one"}))
	must(t, s.SetLimit("lab", "NOBODY", true, nil))
	return s
}

func limitOf(s *Store, ns, name string) *UseLimit {
	sec, _ := s.GetSecret(ns, name)
	return sec.Limit
}

// A limit is outside every view up to v6, so the release with MAC6 never
// sees one, and taking the view leaves the state's limits alone.
func TestLimitOutsideV6View(t *testing.T) {
	s := limited(t, t.TempDir())
	s.mu.Lock()
	defer s.mu.Unlock()
	v6 := s.st.v6View()
	for _, k := range []string{"lab/CF", "lab/NOBODY"} {
		if v6.Secrets[k].Limit != nil {
			t.Fatalf("%s: limit in the v6 view", k)
		}
		if s.st.Secrets[k].Limit == nil {
			t.Fatalf("%s: taking the view lifted the limit", k)
		}
	}
	if b, _ := json.Marshal(v6); strings.Contains(string(b), `"limit"`) {
		t.Fatalf("v6 view: %s", b)
	}
}

// The first limit makes the key check v7, which also requires MAC4; the
// file reopens, and stays v7 after the last limit is lifted, the way v4
// stays after the last MAC4 field goes.
func TestLimitKeyCheck(t *testing.T) {
	dir := t.TempDir()
	s, err := Open(dir, key32())
	must(t, err)
	_, err = s.CreateToken("one", []string{"lab"}, PermRead, nil)
	must(t, err)
	must(t, s.PutValue("lab", "CF", []byte("v"), nil))
	if s.FormatV7() || s.FormatV4() || keyCheckOf(t, dir) != keyCheckMAC {
		t.Fatal("v7 before any limit")
	}
	must(t, s.SetLimit("lab", "CF", true, []string{"one"}))
	if kc := keyCheckOf(t, dir); kc != keyCheckV7 || !s.FormatV7() || !s.FormatV4() {
		t.Fatalf("key check after the first limit: %q", kc)
	}
	data, _ := os.ReadFile(filepath.Join(dir, stateFile))
	for _, f := range []string{`"limit"`, `"mac7"`, `"mac4"`} {
		if !strings.Contains(string(data), f) {
			t.Fatalf("no %s in the file", f)
		}
	}
	s2, err := Open(dir, key32())
	must(t, err)
	if l := limitOf(s2, "lab", "CF"); l == nil || !slices.Equal(l.Tokens, []string{"one"}) {
		t.Fatalf("limit after reopening: %+v", l)
	}
	// Saving v4 fields afterwards never writes the v4 key check over v7.
	_, err = s2.CreateTokenExpiring("temp", []string{"lab"}, PermRead, nil, 30)
	must(t, err)
	must(t, s2.SetLimit("lab", "CF", false, nil))
	must(t, s2.SetTokenExpiry("temp", nil))
	if kc := keyCheckOf(t, dir); kc != keyCheckV7 || !s2.FormatV7() {
		t.Fatalf("key check after the limit is lifted: %q", kc)
	}
	data, _ = os.ReadFile(filepath.Join(dir, stateFile))
	if strings.Contains(string(data), `"limit"`) || !strings.Contains(string(data), `"mac7"`) || !strings.Contains(string(data), `"mac4"`) {
		t.Fatal("v7 with no limit left must still write mac7 and mac4")
	}
	s3, err := Open(dir, key32())
	must(t, err)
	if !s3.FormatV7() {
		t.Fatal("v7 lost on reopening")
	}
}

// A limit is covered by mac7, and because the key check says mac7 is
// required, stripping every limit together with mac7 is refused too: that
// would make the keys usable by every agent again.
func TestLimitIntegrity(t *testing.T) {
	dir := t.TempDir()
	limited(t, dir)
	path := filepath.Join(dir, stateFile)
	data, _ := os.ReadFile(path)
	try := func(name string, edit func(raw map[string]any), want error) {
		t.Helper()
		var raw map[string]any
		must(t, json.Unmarshal(data, &raw))
		edit(raw)
		b, _ := json.Marshal(raw)
		os.WriteFile(path, b, 0o600)
		_, err := Open(dir, key32())
		if !errors.Is(err, want) && !(want == nil && err == nil) {
			t.Fatalf("%s: %v, want %v", name, err, want)
		}
	}
	sec := func(raw map[string]any, k string) map[string]any {
		return raw["secrets"].(map[string]any)[k].(map[string]any)
	}
	strip := func(raw map[string]any) {
		delete(raw, "mac7")
		delete(raw, "notify")
		for _, v := range raw["secrets"].(map[string]any) {
			delete(v.(map[string]any), "limit")
			delete(v.(map[string]any), "versions")
		}
	}
	try("unchanged", func(map[string]any) {}, nil)
	try("token added", func(raw map[string]any) {
		sec(raw, "lab/CF")["limit"] = map[string]any{"tokens": []any{"one", "two"}}
	}, ErrIntegrity)
	try("empty limit filled", func(raw map[string]any) {
		sec(raw, "lab/NOBODY")["limit"] = map[string]any{"tokens": []any{"two"}}
	}, ErrIntegrity)
	try("limit dropped", func(raw map[string]any) { delete(sec(raw, "lab/CF"), "limit") }, ErrIntegrity)
	try("limit moved", func(raw map[string]any) {
		sec(raw, "lab/DECOY")["limit"] = sec(raw, "lab/CF")["limit"]
		delete(sec(raw, "lab/CF"), "limit")
	}, ErrIntegrity)
	try("mac7 dropped", func(raw map[string]any) { delete(raw, "mac7") }, ErrIntegrity)
	try("mac4 dropped", func(raw map[string]any) { delete(raw, "mac4") }, ErrIntegrity)
	// What v0.1.3 would write, which notify and versions alone may be
	// stripped to: refused here, since the key check requires mac7.
	try("limits and mac7 stripped", strip, ErrIntegrity)
	try("and the v4 fields too", func(raw map[string]any) { strip(raw); stripCanary(raw) }, ErrIntegrity)
}

// The key check is sealed, and every MAC covers it, so one copied from an
// older copy of the data (here the same file before the first limit)
// doesn't verify in this file: swapping it in to strip the limits is
// refused. What no MAC can stop is putting back that whole older copy:
// it loads, without the limits it never had (see the design doc).
func TestLimitOlderKeyCheckCopied(t *testing.T) {
	dir := t.TempDir()
	canaried(t, dir)
	path := filepath.Join(dir, stateFile)
	before, _ := os.ReadFile(path)
	s, err := Open(dir, key32())
	must(t, err)
	_, err = s.CreateToken("one", []string{"lab"}, PermRead, nil)
	must(t, err)
	must(t, s.SetLimit("lab", "CF", true, nil))
	var old, raw map[string]any
	must(t, json.Unmarshal(before, &old))
	after, _ := os.ReadFile(path)
	must(t, json.Unmarshal(after, &raw))
	raw["key_check"] = old["key_check"] // the v4 key check
	delete(raw, "mac7")
	delete(raw["secrets"].(map[string]any)["lab/CF"].(map[string]any), "limit")
	b, _ := json.Marshal(raw)
	os.WriteFile(path, b, 0o600)
	if _, err := Open(dir, key32()); !errors.Is(err, ErrIntegrity) {
		t.Fatalf("an older key check swapped in: %v", err)
	}
	os.WriteFile(path, before, 0o600)
	s2, err := Open(dir, key32())
	if err != nil {
		t.Fatalf("the whole older copy put back: %v", err)
	}
	if limitOf(s2, "lab", "CF") != nil || s2.FormatV7() {
		t.Fatal("limit in a copy from before it")
	}
}

// v0.1.3 accepts only the v1, v2 and v4 key checks, so it refuses a file
// with a limit. downgrade-data's first step lifts every limit, reports the
// keys and puts back the v4 key check; then v0.1.3 verifies every MAC it
// knows, and what it writes back opens here. The next steps still work.
func TestDowngradeV7(t *testing.T) {
	dir := t.TempDir()
	limited(t, dir)
	if kc := keyCheckOf(t, dir); slices.Contains([]string{keyCheckV1, keyCheckMAC, keyCheckV4}, kc) {
		t.Fatalf("key check %q: v0.1.3 would accept the file", kc)
	}
	s, err := OpenExisting(dir, key32())
	must(t, err)
	if _, _, err := s.DowngradeV4(); err == nil {
		t.Fatal("DowngradeV4 ran with limits in place")
	}
	if _, err := s.Downgrade(); err == nil {
		t.Fatal("Downgrade ran with limits in place")
	}
	keys, changed, err := s.DowngradeV7()
	if err != nil || !changed || !slices.Equal(keys, []string{"lab/CF", "lab/NOBODY"}) {
		t.Fatalf("DowngradeV7: %v %v %v", keys, changed, err)
	}
	if _, changed, _ := s.DowngradeV7(); changed || s.FormatV7() || !s.FormatV4() {
		t.Fatal("downgraded twice, or v4 lost")
	}
	if kc := keyCheckOf(t, dir); kc != keyCheckV4 {
		t.Fatalf("key check after DowngradeV7: %q", kc)
	}
	path := filepath.Join(dir, stateFile)
	data, _ := os.ReadFile(path)
	if strings.Contains(string(data), `"limit"`) {
		t.Fatal("a limit is left")
	}
	var st state
	must(t, json.Unmarshal(data, &st))
	v6 := mac6Release(st)
	k, _ := newStore(dir, key32())
	for _, c := range []struct {
		name     string
		mac, key []byte
		view     state
	}{
		{"mac", v6.MAC, k.macKey, v6.legacyView()}, {"mac2", v6.MAC2, k.mac2Key, v6.v2View()},
		{"mac3", v6.MAC3, k.mac3Key, v6.v3View()}, {"mac4", v6.MAC4, k.mac4Key, v6.v4View()},
		{"mac5", v6.MAC5, k.mac5Key, v6.v5View()},
	} {
		if !hmacEqual(c.mac, macOf(c.key, &c.view)) {
			t.Fatalf("%s would not verify in v0.1.3", c.name)
		}
	}
	if !checkMAC6(k, v6) {
		t.Fatal("mac6 would not verify in v0.1.3")
	}
	b, _ := json.MarshalIndent(&v6, "", "  ")
	os.WriteFile(path, b, 0o600)
	s2, err := Open(dir, key32())
	if err != nil {
		t.Fatalf("open after v0.1.3 wrote it: %v", err)
	}
	if v, _, _ := s2.Reveal("lab", "CF", ""); string(v) != "compat-value" {
		t.Fatal("value lost")
	}
	// Limits work again, and v7 comes back with them.
	must(t, s2.SetLimit("lab", "CF", true, []string{"one"}))
	if keyCheckOf(t, dir) != keyCheckV7 {
		t.Fatal("v7 didn't come back")
	}
	must(t, s2.SetLimit("lab", "CF", false, nil))
	s3, err := OpenExisting(dir, key32())
	must(t, err)
	if _, _, err := s3.DowngradeV7(); err != nil {
		t.Fatal(err)
	}
	// The existing steps go on from there.
	if _, changed, err := s3.DowngradeV4(); err != nil || !changed {
		t.Fatalf("DowngradeV4 after DowngradeV7: %v %v", changed, err)
	}
	if changed, err := s3.Downgrade(); err != nil || !changed {
		t.Fatalf("Downgrade after DowngradeV4: %v %v", changed, err)
	}
}

func TestSetLimit(t *testing.T) {
	dir := t.TempDir()
	s := limited(t, dir)
	_, err := s.CreateToken("other", []string{"elsewhere"}, PermRead, nil)
	must(t, err)
	must(t, s.PutValue("lab", "VAR", []byte("plain"), &Meta{Variable: true}))
	for _, c := range []struct {
		name   string
		tokens []string
		want   error
	}{{"CF", []string{"nope"}, ErrLimitToken}, {"CF", []string{"other"}, ErrLimitToken}, {"VAR", nil, ErrLimitVariable}, {"MISSING", nil, ErrNotFound}} {
		if err := s.SetLimit("lab", c.name, true, c.tokens); !errors.Is(err, c.want) {
			t.Fatalf("%s %v: %v, want %v", c.name, c.tokens, err, c.want)
		}
	}
	if l := limitOf(s, "lab", "CF"); !slices.Equal(l.Tokens, []string{"one"}) {
		t.Fatalf("a refused limit changed it: %+v", l)
	}
	must(t, s.SetLimit("lab", "CF", true, []string{"two", "one", "two"}))
	if l := limitOf(s, "lab", "CF"); !slices.Equal(l.Tokens, []string{"one", "two"}) {
		t.Fatalf("limit: %+v", l)
	}
	sec, _ := s.GetSecret("lab", "NOBODY")
	if sec.Limit == nil || sec.UsableBy("one") || sec.UsableBy("") {
		t.Fatal("an empty limit must mean no agent")
	}
	if sec, _ := s.GetSecret("lab", "DECOY"); !sec.UsableBy("anyone") {
		t.Fatal("no limit must mean any agent")
	}
	// A limit isn't history: agents read the history.
	n := len(s.History(nil, 1000))
	must(t, s.SetLimit("lab", "CF", false, nil))
	must(t, s.SetLimit("lab", "CF", true, []string{"two"}))
	if len(s.History(nil, 1000)) != n {
		t.Fatal("a limit was recorded in the history")
	}
}

// A revoked token comes off every limit, so a new token with its name has
// no access; a limit left empty stays a limit. Renewal keeps the name and
// the access. Losing the namespace takes the token off that namespace's
// limits, and granting it again doesn't put it back.
func TestLimitTokenLifecycle(t *testing.T) {
	dir := t.TempDir()
	s := limited(t, dir)
	_, err := s.CreateTokenExpiring("ren", []string{"lab", "ops"}, PermRead, nil, 30)
	must(t, err)
	must(t, s.PutValue("ops", "OPS", []byte("ops-value"), nil))
	must(t, s.SetLimit("lab", "DECOY", true, []string{"ren", "two"}))
	must(t, s.SetLimit("ops", "OPS", true, []string{"ren"}))
	if _, err := s.RotateToken("ren", 90); err != nil {
		t.Fatal(err)
	}
	if !s.st.Secrets["lab/DECOY"].UsableBy("ren") {
		t.Fatal("a renewal lost the token's place")
	}
	must(t, s.RevokeToken("one"))
	if l := limitOf(s, "lab", "CF"); l == nil || len(l.Tokens) != 0 {
		t.Fatalf("after revoking the only token on it: %+v", l)
	}
	_, err = s.CreateToken("one", []string{"lab"}, PermRead, nil)
	must(t, err)
	if s.st.Secrets["lab/CF"].UsableBy("one") {
		t.Fatal("a new token with a revoked token's name inherited its access")
	}
	must(t, s.SetTokenNamespaces("ren", []string{"ops"}))
	if l := limitOf(s, "lab", "DECOY"); !slices.Equal(l.Tokens, []string{"two"}) {
		t.Fatalf("after ren lost lab: %+v", l)
	}
	if l := limitOf(s, "ops", "OPS"); !slices.Equal(l.Tokens, []string{"ren"}) {
		t.Fatalf("ren's place in ops went too: %+v", l)
	}
	must(t, s.SetTokenNamespaces("ren", []string{"ops", "lab"}))
	if s.st.Secrets["lab/DECOY"].UsableBy("ren") {
		t.Fatal("granting the namespace again put the place back")
	}
	// The same through a reopen.
	s2, err := Open(dir, key32())
	must(t, err)
	if l := limitOf(s2, "lab", "DECOY"); !slices.Equal(l.Tokens, []string{"two"}) {
		t.Fatalf("after reopening: %+v", l)
	}
}

// Limits are for secrets: no path turns a limited key into a variable,
// and each refusal leaves the key as it was.
func TestLimitVariables(t *testing.T) {
	dir := t.TempDir()
	s := limited(t, dir)
	_, err := s.CreateToken("writer", []string{"lab"}, PermWrite, nil)
	must(t, err)
	must(t, s.SetLimit("lab", "CF", true, []string{"writer"}))
	must(t, s.PutValue("lab", "CF", []byte("as-variable-once"), &Meta{}))
	must(t, s.SetValue("lab", "CF", []byte("secret-again"), false))
	// An older value that was a variable, to restore.
	must(t, s.SetLimit("lab", "NOBODY", false, nil))
	must(t, s.SetValue("lab", "NOBODY", []byte("var-value"), true))
	must(t, s.SetValue("lab", "NOBODY", []byte("secret-value"), false))
	must(t, s.SetLimit("lab", "NOBODY", true, nil))
	before, _ := os.ReadFile(filepath.Join(dir, stateFile))
	writer := s.st.Tokens["writer"]
	for name, f := range map[string]func() error{
		"admin value": func() error { return s.SetValue("lab", "CF", []byte("x"), true) },
		"put meta":    func() error { return s.PutValue("lab", "CF", []byte("x"), &Meta{Variable: true}) },
		"details":     func() error { return s.UpdateMeta("lab", "CF", Meta{Variable: true}) },
		"agent put": func() error {
			_, err := s.AgentPut("lab", "CF", []byte("x"), AgentPut{Token: *writer, Overwrite: true, Variable: true})
			return err
		},
		"restore": func() error { _, _, err := s.Restore("lab", "NOBODY", ""); return err },
	} {
		if err := f(); !errors.Is(err, ErrLimitVariable) {
			t.Fatalf("%s: %v", name, err)
		}
		if after, _ := os.ReadFile(filepath.Join(dir, stateFile)); string(after) != string(before) {
			t.Fatalf("%s: the refusal changed the file", name)
		}
		if sec, _ := s.GetSecret("lab", "CF"); sec.Variable || sec.Limit == nil {
			t.Fatalf("%s: %+v", name, sec)
		}
	}
	// Lifting the limit first works.
	must(t, s.SetLimit("lab", "CF", false, nil))
	must(t, s.UpdateMeta("lab", "CF", Meta{Variable: true}))
}

// A failed save leaves the limit, and the key check, as they were; the
// snapshot and the copies handed out don't share the list.
func TestLimitSnapshot(t *testing.T) {
	dir := t.TempDir()
	s, err := Open(dir, key32())
	must(t, err)
	_, err = s.CreateToken("one", []string{"lab"}, PermRead, nil)
	must(t, err)
	must(t, s.PutValue("lab", "CF", []byte("v"), nil))
	path := s.path
	s.path = filepath.Join(dir, "missing", stateFile)
	if err := s.SetLimit("lab", "CF", true, []string{"one"}); err == nil {
		t.Fatal("save didn't fail")
	}
	if limitOf(s, "lab", "CF") != nil || s.v7 || s.v4 || s.FormatV7() {
		t.Fatal("a failed save left the limit or v7")
	}
	s.path = path
	must(t, s.SetLimit("lab", "CF", true, []string{"one"}))
	snap := s.st.clone()
	cp, _ := s.GetSecret("lab", "CF")
	cp.Limit.Tokens[0] = "changed"
	must(t, s.RevokeToken("one"))
	if l := snap.Secrets["lab/CF"].Limit; !slices.Equal(l.Tokens, []string{"one"}) {
		t.Fatalf("the snapshot shares the list: %+v", l)
	}
	if l := limitOf(s, "lab", "CF"); len(l.Tokens) != 0 {
		t.Fatalf("after the revoke: %+v", l)
	}
	s.path = filepath.Join(dir, "missing", stateFile)
	if err := s.SetLimit("lab", "CF", false, nil); err == nil {
		t.Fatal("save didn't fail")
	}
	if limitOf(s, "lab", "CF") == nil {
		t.Fatal("a failed save lifted the limit")
	}
}

// The store refuses a token off a key's limit whatever the caller: no
// value, no write, no ack, and never new to it. A refusal on a canary is
// a touch. The admin's own calls aren't limited.
func TestLimitEnforced(t *testing.T) {
	dir := t.TempDir()
	s := limited(t, dir)
	two := s.st.Tokens["two"]
	if sec, _ := s.GetSecret("lab", "CF"); !sec.NewFor("one") || sec.NewFor("two") {
		t.Fatal("new: only to a token that may read it")
	}
	if v, _, _, err := s.AgentReveal("lab", "CF", "one", "10.0.0.1"); err != nil || string(v) != "compat-value" {
		t.Fatalf("listed: %q %v", v, err)
	}
	for _, name := range []string{"CF", "NOBODY"} {
		if v, _, hit, err := s.AgentReveal("lab", name, "two", "10.0.0.2"); !errors.Is(err, ErrLimited) || v != nil || hit != nil {
			t.Fatalf("%s off the list: %q %v %v", name, v, hit, err)
		}
		if _, err := s.AgentAck("lab", name, AgentCtx{"two", ""}); !errors.Is(err, ErrLimited) {
			t.Fatalf("%s ack: %v", name, err)
		}
		for _, ow := range []bool{true, false} {
			if _, err := s.AgentPut("lab", name, []byte("x"), AgentPut{Token: *two, Overwrite: ow}); !errors.Is(err, ErrLimited) {
				t.Fatalf("%s put (overwrite %v): %v", name, ow, err)
			}
		}
	}
	// The admin isn't a token.
	if v, _, err := s.Reveal("lab", "NOBODY", "admin (web)"); err != nil || string(v) != "nobody-value" {
		t.Fatalf("admin reveal: %v", err)
	}
	must(t, s.SetValue("lab", "NOBODY", []byte("admin-value"), false))
	// A canary: the refusal is a touch, the same answer otherwise.
	must(t, s.SetLimit("lab", "DECOY", true, []string{"one"}))
	if _, _, hit, err := s.AgentReveal("lab", "DECOY", "two", "10.0.0.2"); !errors.Is(err, ErrLimited) || hit == nil || hit.Action != "reveal" {
		t.Fatalf("canary reveal: %v %+v", err, hit)
	}
	if hit, err := s.AgentAck("lab", "DECOY", AgentCtx{"two", ""}); !errors.Is(err, ErrLimited) || hit == nil || hit.Action != "ack" {
		t.Fatalf("canary ack: %v %+v", err, hit)
	}
	if res, err := s.AgentPut("lab", "DECOY", []byte("x"), AgentPut{Token: *two, Overwrite: true}); !errors.Is(err, ErrLimited) || res.Canary == nil {
		t.Fatalf("canary put: %v %+v", err, res)
	}
}
