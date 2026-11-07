package store

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

// canaried makes a store using every field outside v3View: an expiring
// token, a canary, a canary read and the revoke-on-read setting.
func canaried(t *testing.T, dir string) *Store {
	t.Helper()
	s := grouped(t, dir)
	if _, err := s.CreateTokenExpiring("temp", []string{"lab"}, PermRead, nil, 90); err != nil {
		t.Fatal(err)
	}
	if _, created, err := s.RequestRenewal("temp", "10.0.0.9"); err != nil || !created {
		t.Fatalf("renewal request: %v %v", created, err)
	}
	if _, err := s.CreateTokenExpiring("rot", []string{"lab"}, PermRead, nil, 30); err != nil {
		t.Fatal(err)
	}
	if _, err := s.RotateToken("rot", 90); err != nil {
		t.Fatal(err)
	}
	must(t, s.PutValue("lab", "DECOY", []byte("decoy-value"), nil))
	must(t, s.SetCanary("lab", "DECOY", true))
	if _, _, hit, err := s.AgentReveal("lab", "DECOY", "adder", "10.0.0.9"); err != nil || hit == nil {
		t.Fatalf("canary read: %v %v", hit, err)
	}
	must(t, s.SetRevokeOnCanary(false)) // stored as nothing; set again below
	must(t, s.SetRevokeOnCanary(true))
	return s
}

// downgraded is canaried after `keydrop downgrade-data`.
func downgraded(t *testing.T, dir string) V4Dropped {
	t.Helper()
	canaried(t, dir)
	s, err := OpenExisting(dir, key32())
	if err != nil {
		t.Fatal(err)
	}
	if !s.FormatV4() {
		t.Fatal("using the MAC4 fields didn't make MAC4 required")
	}
	d, changed, err := s.DowngradeV4()
	if err != nil || !changed {
		t.Fatalf("downgrade: %v %v", changed, err)
	}
	if _, changed, _ := s.DowngradeV4(); changed {
		t.Fatal("downgraded twice")
	}
	return d
}

// keyCheckOf decrypts the key check in dir's state file.
func keyCheckOf(t *testing.T, dir string) string {
	t.Helper()
	data, _ := os.ReadFile(filepath.Join(dir, stateFile))
	var st state
	must(t, json.Unmarshal(data, &st))
	s, _ := newStore(dir, key32())
	pt, err := s.open(st.KeyCheck, "keycheck")
	must(t, err)
	return string(pt)
}

// Once the MAC4 fields are used, the key check requires MAC4, which the
// release before them (5f2f64e) doesn't know: it refuses the file until
// downgrade-data. That drops the fields, and then that release parses
// everything, checks mac, mac2 and mac3 over what it parsed, and what it
// writes back opens here.
func TestV3ReleaseReadsCanaryFile(t *testing.T) {
	dir := t.TempDir()
	canaried(t, dir)
	path := filepath.Join(dir, stateFile)
	data, _ := os.ReadFile(path)
	for _, f := range []string{`"canary"`, `"expires_at"`, `"lifetime_days"`, `"renewal"`, `"rotation"`, `"hits"`, `"revoke_on_read"`, `"mac4"`, `"mac3"`, `"groups"`} {
		if !strings.Contains(string(data), f) {
			t.Fatalf("no %s in the file", f)
		}
	}
	if kc := keyCheckOf(t, dir); kc != keyCheckV4 {
		t.Fatalf("key check %q: the older release would accept the file", kc)
	}
	dir = t.TempDir()
	d := downgraded(t, dir)
	if !slices.Equal(d.Expiring, []string{"temp"}) || !slices.Equal(d.Renewals, []string{"temp"}) || !slices.Equal(d.Unpaired, []string{"rot"}) ||
		!slices.Equal(d.Canaries, []string{"lab/DECOY"}) || d.CanaryHits != 1 || !d.RevokeOn {
		t.Fatalf("dropped: %+v", d)
	}
	if kc := keyCheckOf(t, dir); kc != keyCheckMAC {
		t.Fatalf("key check after downgrade-data: %q", kc)
	}
	path = filepath.Join(dir, stateFile)
	data, _ = os.ReadFile(path)
	for _, f := range []string{`"canary"`, `"expires_at"`, `"lifetime_days"`, `"renewal"`, `"rotation"`, `"mac4"`} {
		if strings.Contains(string(data), f) {
			t.Fatalf("downgrade-data kept %s", f)
		}
	}
	var st state
	must(t, json.Unmarshal(data, &st))
	v3 := st.v3View()
	v3.MAC, v3.MAC2, v3.MAC3 = st.MAC, st.MAC2, st.MAC3
	s, _ := newStore(dir, key32())
	legacy := v3.legacyView()
	if !hmacEqual(v3.MAC, macOf(s.macKey, &legacy)) {
		t.Fatal("mac would not verify in the v3 release")
	}
	v2 := v3.v2View()
	if !hmacEqual(v3.MAC2, macOf(s.mac2Key, &v2)) {
		t.Fatal("mac2 would not verify in the v3 release")
	}
	check := v3
	check.MAC, check.MAC2, check.MAC3 = nil, nil, nil
	if !hmacEqual(v3.MAC3, macOf(s.mac3Key, &check)) {
		t.Fatal("mac3 would not verify in the v3 release")
	}
	// The v3 release saves the same thing back.
	b, _ := json.MarshalIndent(&v3, "", "  ")
	os.WriteFile(path, b, 0o600)
	s2, err := Open(dir, key32())
	if err != nil {
		t.Fatalf("open after the v3 release wrote it: %v", err)
	}
	if tok := s2.st.Tokens["temp"]; tok == nil || tok.ExpiresAt != nil || tok.Renewal != nil || tok.Lifetime != 0 {
		t.Fatalf("temp after the v3 release: %+v", tok)
	}
	if _, ok := s2.st.Tokens["rot"]; ok {
		t.Fatal("a token whose renewal was never collected survived")
	}
	if sec, _ := s2.GetSecret("lab", "DECOY"); sec.Canary || !sec.HasValue() {
		t.Fatalf("DECOY after the v3 release: %+v", sec)
	}
	if h, _ := s2.CanaryHits(); len(h) != 0 || s2.RevokeOnCanary() || s2.FormatV4() {
		t.Fatal("canary state survived")
	}
	// Everything older is intact.
	if sec, _ := s2.GetSecret("lab", "CF"); sec.Ext == nil || sec.Group == "" {
		t.Fatalf("CF after the v3 release: %+v", sec)
	}
	if v, _, _ := s2.Reveal("lab", "DECOY", ""); string(v) != "decoy-value" {
		t.Fatal("value lost")
	}
	// And using the fields again makes MAC4 required again.
	if _, err := s2.CreateTokenExpiring("again", []string{"lab"}, PermRead, nil, 30); err != nil || keyCheckOf(t, dir) != keyCheckV4 {
		t.Fatalf("v4 again: %v", err)
	}
}

// The canary and expiry fields are covered by mac4.
func TestCanaryFieldsIntegrity(t *testing.T) {
	dir := t.TempDir()
	canaried(t, dir)
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
	secrets := func(raw map[string]any) map[string]any { return raw["secrets"].(map[string]any) }
	tokens := func(raw map[string]any) map[string]any { return raw["tokens"].(map[string]any) }
	try("expiry moved", func(raw map[string]any) {
		tokens(raw)["temp"].(map[string]any)["expires_at"] = "2099-01-01T00:00:00Z"
	}, ErrIntegrity)
	try("expiry dropped", func(raw map[string]any) {
		delete(tokens(raw)["temp"].(map[string]any), "expires_at")
	}, ErrIntegrity)
	try("rotation dropped", func(raw map[string]any) {
		delete(tokens(raw)["rot"].(map[string]any), "rotation")
	}, ErrIntegrity)
	try("renewal request dropped", func(raw map[string]any) {
		delete(tokens(raw)["temp"].(map[string]any), "renewal")
	}, ErrIntegrity)
	try("canary cleared", func(raw map[string]any) {
		delete(secrets(raw)["lab/DECOY"].(map[string]any), "canary")
	}, ErrIntegrity)
	try("hit dropped", func(raw map[string]any) {
		raw["canary"].(map[string]any)["hits"] = []any{}
	}, ErrIntegrity)
	try("mac4 dropped", func(raw map[string]any) { delete(raw, "mac4") }, ErrIntegrity)
	try("group changed", func(raw map[string]any) {
		secrets(raw)["lab/CF"].(map[string]any)["group"] = "x"
	}, ErrIntegrity)
	// All of them stripped together, which would be the file the v3
	// release writes: refused, since the key check says MAC4 is required.
	// These fields restrict access, so losing them must never be silent.
	try("canary fields stripped", stripCanary, ErrIntegrity)
	try("expiry added without mac4", func(raw map[string]any) {
		stripCanary(raw)
		tokens(raw)["adder"].(map[string]any)["expires_at"] = "2099-01-01T00:00:00Z"
	}, ErrIntegrity)
}

func stripCanary(raw map[string]any) {
	delete(raw, "mac4")
	delete(raw, "canary")
	for _, v := range raw["secrets"].(map[string]any) {
		delete(v.(map[string]any), "canary")
	}
	for _, v := range raw["tokens"].(map[string]any) {
		delete(v.(map[string]any), "expires_at")
		delete(v.(map[string]any), "lifetime_days")
		delete(v.(map[string]any), "renewal")
		delete(v.(map[string]any), "rotation")
	}
}

func TestTokenExpiry(t *testing.T) {
	now := time.Date(2026, 11, 1, 12, 0, 0, 0, time.UTC)
	s, _ := Open(t.TempDir(), key32())
	s.now = func() time.Time { return now }
	if _, err := s.CreateTokenExpiring("x", []string{"lab"}, PermRead, nil, 7); !errors.Is(err, ErrBadLifetime) {
		t.Fatalf("7 days: %v", err)
	}
	plain, err := s.CreateTokenExpiring("bot", []string{"lab"}, PermRead, nil, 30)
	must(t, err)
	if tok, err := s.LookupToken(plain, "10.0.0.1"); err != nil || !tok.ExpiresAt.Equal(now.Add(30*24*time.Hour)) || tok.RenewLifetime() != 30 {
		t.Fatalf("fresh: %+v %v", tok, err)
	}
	expiry := now.Add(30 * 24 * time.Hour)
	now = now.Add(31 * 24 * time.Hour)
	tok, err := s.LookupToken(plain, "10.0.0.1")
	if !errors.Is(err, ErrExpired) || tok.Name != "bot" {
		t.Fatalf("expired: %+v %v", tok, err)
	}
	if lu := s.st.Tokens["bot"].LastUsedAt; lu == nil || lu.After(now.Add(-24*time.Hour)) {
		t.Fatal("an expired token's use was recorded")
	}
	// Expired is checked before the source, so it reveals no more.
	must(t, s.SetTokenSources("bot", []string{"10.0.0.0/24"}))
	if _, err := s.LookupToken(plain, "10.9.9.9"); !errors.Is(err, ErrExpired) {
		t.Fatalf("expired, wrong source: %v", err)
	}
	// In the grace window it may only ask for renewal, still from its
	// sources.
	if tok, err := s.LookupTokenForRenewal(plain, "10.0.0.1"); err != nil || !tok.Expired(now) {
		t.Fatalf("renewal lookup: %+v %v", tok, err)
	}
	if _, err := s.LookupTokenForRenewal(plain, "10.9.9.9"); !errors.Is(err, ErrSource) {
		t.Fatalf("renewal lookup, wrong source: %v", err)
	}
	// The grace window is 30 days after expiry.
	now = expiry.Add(RenewalGrace - time.Minute)
	if _, err := s.LookupTokenForRenewal(plain, "10.0.0.1"); err != nil {
		t.Fatalf("29 days after expiry: %v", err)
	}
	now = expiry.Add(RenewalGrace)
	if _, err := s.LookupTokenForRenewal(plain, "10.0.0.1"); !errors.Is(err, ErrExpired) || RenewalGrace != 30*24*time.Hour {
		t.Fatalf("30 days after expiry: %v", err)
	}
	now = expiry.Add(24 * time.Hour)
	req, created, err := s.RequestRenewal("bot", "10.0.0.1")
	if err != nil || !created || req.IP != "10.0.0.1" {
		t.Fatalf("request: %+v %v %v", req, created, err)
	}
	if again, created, err := s.RequestRenewal("bot", "10.0.0.2"); err != nil || created || again != req {
		t.Fatalf("second request: %+v %v %v", again, created, err)
	}
	must(t, s.DeclineRenewal("bot"))
	if err := s.DeclineRenewal("bot"); !errors.Is(err, ErrNotFound) {
		t.Fatal(err)
	}
	s.RequestRenewal("bot", "10.0.0.1")
	// Approved: the token's hash is the new token's straight away; the old
	// one is kept only to collect it.
	oldHash := s.st.Tokens["bot"].Hash
	rot, err := s.RotateToken("bot", 180)
	if err != nil || rot.Sealed != nil || rot.OldHash != "" || rot.IP != "10.0.0.1" || !rot.CollectBy.Equal(now.Add(RotationCollectWindow)) {
		t.Fatalf("rotate: %+v %v", rot, err)
	}
	if cur := s.st.Tokens["bot"]; cur.Hash == oldHash || cur.Rotation.OldHash != oldHash || !cur.ExpiresAt.Equal(now.Add(180*24*time.Hour)) {
		t.Fatalf("after rotate: %+v", cur)
	}
	if _, err := s.LookupToken(plain, "10.0.0.1"); !errors.Is(err, ErrRotated) {
		t.Fatalf("old token after approval: %v", err)
	}
	if _, _, err := s.RequestRenewal("bot", ""); !errors.Is(err, ErrRotated) {
		t.Fatalf("renewal after approval: %v", err)
	}
	if _, err := s.LookupTokenForRenewal(plain, "10.9.9.9"); !errors.Is(err, ErrSource) {
		t.Fatalf("collect from a wrong source: %v", err)
	}
	old, err := s.LookupTokenForRenewal(plain, "10.0.0.1")
	if err != nil || old.Rotation == nil {
		t.Fatalf("old token for collecting: %+v %v", old, err)
	}
	if strings.Contains(string(s.st.Tokens["bot"].Rotation.Sealed), "kd_") {
		t.Fatal("new token stored in the clear")
	}
	// Only from the address that asked for the renewal.
	old2, _ := s.LookupTokenForRenewal(plain, "10.0.0.2")
	if _, _, err := s.CollectRotation(old2, "10.0.0.2"); !errors.Is(err, ErrCollectIP) {
		t.Fatalf("collect from another address: %v", err)
	}
	newPlain, tok, err := s.CollectRotation(old, "10.0.0.1")
	if err != nil || newPlain == plain || !strings.HasPrefix(newPlain, TokenPrefix) || tok.RenewLifetime() != 180 || tok.Rotation != nil {
		t.Fatalf("collect: %+v %v", tok, err)
	}
	// The answer was lost: collecting again gives the same token, until
	// the new token is used.
	if again, _, err := s.CollectRotation(old, "10.0.0.1"); err != nil || again != newPlain {
		t.Fatalf("collect again: %v", err)
	}
	if _, err := s.RotateToken("bot", 90); !errors.Is(err, ErrCollecting) {
		t.Fatalf("rotate while collected but unused: %v", err)
	}
	if tok, err := s.LookupToken(newPlain, "10.0.0.1"); err != nil || tok.Name != "bot" || tok.Sources[0] != "10.0.0.0/24" {
		t.Fatalf("new token: %+v %v", tok, err)
	}
	if s.st.Tokens["bot"].Rotation != nil {
		t.Fatal("rotation kept after the new token's first use")
	}
	if _, _, err := s.CollectRotation(old, "10.0.0.1"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("collect after the new token was used: %v", err)
	}
	for _, lookup := range []func(string, string) (Token, error){s.LookupToken, s.LookupTokenForRenewal} {
		if _, err := lookup(plain, "10.0.0.1"); !errors.Is(err, ErrNotFound) {
			t.Fatalf("old token after the new one was used: %v", err)
		}
	}
	if _, err := s.RotateToken("bot", 5); !errors.Is(err, ErrBadLifetime) {
		t.Fatal(err)
	}
	plain = newPlain
	// Approved but not collected in time: deleted, the agent pairs again.
	s.RotateToken("bot", 30)
	if gone := s.RevokeUncollectedRotations(now); len(gone) != 0 {
		t.Fatalf("revoked early: %v", gone)
	}
	now = now.Add(RotationCollectWindow)
	if _, err := s.LookupTokenForRenewal(plain, "10.0.0.1"); !errors.Is(err, ErrExpired) {
		t.Fatalf("past the collect window: %v", err)
	}
	if gone := s.RevokeUncollectedRotations(now); len(gone) != 1 || gone[0] != "bot" {
		t.Fatalf("uncollected: %v", gone)
	}
	// Collected but never used in the window: the token stays, the old
	// hash goes.
	p2, _ := s.CreateTokenExpiring("bot2", []string{"lab"}, PermRead, nil, 30)
	s.LookupToken(p2, "10.0.0.3")
	s.RotateToken("bot2", 30)
	o2, _ := s.LookupTokenForRenewal(p2, "10.0.0.3")
	if _, _, err := s.CollectRotation(o2, "10.0.0.3"); err != nil {
		t.Fatal(err)
	}
	now = now.Add(RotationCollectWindow)
	if gone := s.RevokeUncollectedRotations(now); len(gone) != 0 || s.st.Tokens["bot2"] == nil || s.st.Tokens["bot2"].Rotation != nil {
		t.Fatalf("collected, unused: %v", gone)
	}
	// Never.
	nv, _ := s.CreateTokenExpiring("nv", []string{"lab"}, PermRead, nil, 0)
	if _, _, err := s.RequestRenewal("nv", ""); !errors.Is(err, ErrNoExpiry) {
		t.Fatalf("never-expiring renewal: %v", err)
	}
	if tok, err := s.LookupToken(nv, ""); err != nil || tok.ExpiresAt != nil {
		t.Fatal(err)
	}
	if _, err := s.RotateToken("nobody", 30); !errors.Is(err, ErrNotFound) {
		t.Fatal(err)
	}
	// The older creator makes never-expiring tokens, and alone doesn't
	// need MAC4.
	s3, _ := Open(t.TempDir(), key32())
	s3.CreateToken("old", []string{"lab"}, PermRead, nil)
	if s3.st.Tokens["old"].ExpiresAt != nil || s3.st.hasNewer4() || s3.FormatV4() {
		t.Fatal("CreateToken set an expiry")
	}
}

func TestCanary(t *testing.T) {
	s, _ := Open(t.TempDir(), key32())
	s.CreateToken("alice", []string{"lab"}, PermWrite, nil)
	s.CreateToken("bob", []string{"lab"}, PermRead, nil)
	must(t, s.PutValue("lab", "DECOY", []byte("fake-but-plausible"), nil))
	must(t, s.PutValue("lab", "REAL", []byte("real-value"), nil))
	must(t, s.PutValue("lab", "URL", []byte("https://x"), &Meta{Variable: true}))
	before, _ := s.GetSecret("lab", "DECOY")
	hist := len(s.History(nil, 1000))
	must(t, s.SetCanary("lab", "DECOY", true))
	if err := s.SetCanary("lab", "URL", true); !errors.Is(err, ErrCanaryVariable) {
		t.Fatalf("variable canary: %v", err)
	}
	if err := s.SetCanary("lab", "NOPE", true); !errors.Is(err, ErrNotFound) {
		t.Fatal(err)
	}
	after, _ := s.GetSecret("lab", "DECOY")
	if !after.Canary || !after.UpdatedAt.Equal(before.UpdatedAt) || len(s.History(nil, 1000)) != hist {
		t.Fatal("marking a canary left a trace agents can see")
	}
	// A read returns the value as usual and records a hit.
	v, variable, hit, err := s.AgentReveal("lab", "DECOY", "alice", "10.0.0.7")
	if err != nil || string(v) != "fake-but-plausible" || variable || hit == nil {
		t.Fatalf("canary read: %q %v %v %v", v, variable, hit, err)
	}
	if hit.Token != "alice" || hit.IP != "10.0.0.7" || hit.Ref() != "lab/DECOY" || hit.Action != "read" || hit.TokenRevoked {
		t.Fatalf("hit: %+v", hit)
	}
	if _, _, hit, _ := s.AgentReveal("lab", "REAL", "alice", "10.0.0.7"); hit != nil {
		t.Fatal("a real secret counted as a canary")
	}
	if _, _, err := s.Reveal("lab", "DECOY", "admin (web)"); err != nil {
		t.Fatal(err)
	}
	if h, _ := s.CanaryHits(); len(h) != 1 {
		t.Fatal("the admin's own reveal counted as a canary read")
	}
	// Writes, status, flags and notes by an agent are touches too, in the
	// same (canary, token) entry.
	for _, f := range []func() (*CanaryTouch, error){
		func() (*CanaryTouch, error) {
			return s.AgentAddFlag("lab", "DECOY", "looks off", "", AgentCtx{"alice", "10.0.0.8"})
		},
		func() (*CanaryTouch, error) {
			return s.AgentSetStatus("lab", "DECOY", "expired", "", AgentCtx{"alice", "10.0.0.7"})
		},
		func() (*CanaryTouch, error) {
			return s.AgentProposeNote("lab", "DECOY", "a note", AgentCtx{"alice", "10.0.0.7"})
		},
	} {
		if h, err := f(); err != nil || h == nil || h.Token != "alice" {
			t.Fatalf("touch: %+v %v", h, err)
		}
	}
	if h, err := s.AgentAddFlag("lab", "REAL", "looks off", "", AgentCtx{"alice", "10.0.0.7"}); err != nil || h != nil {
		t.Fatalf("flag on a real secret: %+v %v", h, err)
	}
	// An agent turning it into a variable can't clear the flag.
	tok := s.st.Tokens["alice"]
	res, err := s.AgentPut("lab", "DECOY", []byte("x"), AgentPut{Token: *tok, Overwrite: true, Variable: true, IP: "10.0.0.7"})
	if err != nil || res.Canary == nil || res.Canary.Action != "write" {
		t.Fatalf("agent write: %+v %v", res, err)
	}
	if sec, _ := s.GetSecret("lab", "DECOY"); !sec.Canary || !sec.Variable {
		t.Fatalf("agent kind change: %+v", sec)
	}
	if _, _, hit, _ := s.AgentReveal("lab", "DECOY", "alice", "10.0.0.7"); hit == nil {
		t.Fatal("a canary an agent made a variable isn't watched")
	}
	h, dropped := s.CanaryHits()
	if len(h) != 1 || dropped != 0 || h[0].Count != 6 || !slices.Equal(h[0].IPs, []string{"10.0.0.7", "10.0.0.8"}) || h[0].Action != "read" || !h[0].Last.After(h[0].First) && !h[0].Last.Equal(h[0].First) {
		t.Fatalf("aggregated: %+v", h)
	}
	// Dismiss.
	must(t, s.DismissCanaryHit(h[0].ID))
	if h, _ := s.CanaryHits(); len(h) != 0 || s.st.Canary != nil {
		t.Fatal("dismissed hit kept")
	}
	if err := s.DismissCanaryHit("x"); !errors.Is(err, ErrNotFound) {
		t.Fatal(err)
	}
	// The admin making it a variable clears it.
	must(t, s.UpdateMeta("lab", "DECOY", Meta{Variable: true}))
	if sec, _ := s.GetSecret("lab", "DECOY"); sec.Canary {
		t.Fatal("variable kept the canary flag")
	}
	must(t, s.UpdateMeta("lab", "DECOY", Meta{}))
	must(t, s.SetCanary("lab", "DECOY", true))
	// Revoke on read.
	must(t, s.SetRevokeOnCanary(true))
	if _, _, hit, err := s.AgentReveal("lab", "DECOY", "bob", "10.0.0.8"); err != nil || hit == nil || !hit.TokenRevoked {
		t.Fatalf("revoke on read: %+v %v", hit, err)
	}
	if _, ok := s.st.Tokens["bob"]; ok {
		t.Fatal("bob not revoked")
	}
	if _, ok := s.st.Tokens["alice"]; !ok {
		t.Fatal("alice revoked")
	}
	must(t, s.PutValue("lab", "R", []byte("was-a-variable"), &Meta{Variable: true}))
	must(t, s.PutValue("lab", "R", []byte("now-a-secret"), &Meta{}))
	must(t, s.SetCanary("lab", "R", true))
	must(t, s.Rollback("lab", "R"))
	if sec, _ := s.GetSecret("lab", "R"); !sec.Variable || sec.Canary {
		t.Fatalf("rolled back to a variable: %+v", sec)
	}
	must(t, s.Rollback("lab", "R"))
	must(t, s.SetCanary("lab", "R", true))
	must(t, s.PutValue("lab", "R", []byte("v"), &Meta{Variable: true}))
	if sec, _ := s.GetSecret("lab", "R"); sec.Canary {
		t.Fatal("put as a variable by the admin kept the canary flag")
	}
}

// One entry per (canary, token), never evicted: past the cap, further
// pairs only count.
func TestCanaryHitCap(t *testing.T) {
	s, _ := Open(t.TempDir(), key32())
	must(t, s.PutValue("lab", "DECOY", []byte("v"), nil))
	must(t, s.SetCanary("lab", "DECOY", true))
	for range 3 {
		s.AgentReveal("lab", "DECOY", "first", "10.0.0.1")
	}
	for i := range maxCanaryHits + 5 {
		s.AgentReveal("lab", "DECOY", fmt.Sprintf("t%d", i), fmt.Sprintf("10.0.%d.%d", i/200, i%200))
	}
	h, dropped := s.CanaryHits()
	if len(h) != maxCanaryHits || dropped != 6 {
		t.Fatalf("%d entries kept, %d dropped", len(h), dropped)
	}
	if i := slices.IndexFunc(h, func(h CanaryHit) bool { return h.Token == "first" }); i < 0 || h[i].Count != 3 {
		t.Fatal("the first hit was evicted")
	}
	for range maxHitIPs + 3 {
		s.AgentReveal("lab", "DECOY", "first", fmt.Sprintf("10.1.0.%d", len(s.st.Canary.Hits[0].IPs)+100))
	}
	if n := len(s.st.Canary.Hits[0].IPs); n != maxHitIPs {
		t.Fatalf("%d addresses kept", n)
	}
	must(t, s.DismissCanaryHit("dropped"))
	if _, dropped := s.CanaryHits(); dropped != 0 {
		t.Fatal("overflow not cleared")
	}
}

func TestDuplicates(t *testing.T) {
	s, _ := Open(t.TempDir(), key32())
	must(t, s.PutValue("lab", "A", []byte("same"), nil))
	must(t, s.PutValue("web", "B", []byte("same"), nil))
	must(t, s.PutValue("lab", "C", []byte("other"), nil))
	must(t, s.PutValue("lab", "U1", []byte("admin"), &Meta{Variable: true}))
	must(t, s.PutValue("lab", "U2", []byte("admin"), &Meta{Variable: true}))
	must(t, s.PutValue("lab", "S", []byte("admin"), nil))
	s.Request("lab", "ASKED", "", "", "")
	d, err := s.Duplicates([]string{"lab/A"})
	if err != nil || len(d) != 1 || d[0] != (Duplicate{"lab/A", "web/B"}) {
		t.Fatalf("A: %+v %v", d, err)
	}
	// Both of a pair saved together: reported once.
	if d, _ := s.Duplicates([]string{"lab/A", "web/B"}); len(d) != 1 {
		t.Fatalf("pair twice: %+v", d)
	}
	if d, _ := s.Duplicates([]string{"lab/C", "lab/ASKED", "lab/NOPE"}); len(d) != 0 {
		t.Fatalf("C: %+v", d)
	}
	// Two variables alike aren't reported; a secret like them is.
	d, _ = s.Duplicates([]string{"lab/U1"})
	if len(d) != 1 || d[0].Other != "lab/S" {
		t.Fatalf("U1: %+v", d)
	}
}
