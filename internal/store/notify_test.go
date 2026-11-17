package store

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestInboxAlertsSetting(t *testing.T) {
	dir := t.TempDir()
	s, err := Open(dir, key32())
	must(t, err)
	path := filepath.Join(dir, stateFile)
	inFile := func() bool {
		data, _ := os.ReadFile(path)
		n, m := strings.Contains(string(data), `"notify"`), strings.Contains(string(data), `"mac7"`)
		if n != m {
			t.Fatalf("notify in the file %v, mac7 %v", n, m)
		}
		return n
	}
	if on, chosen := s.InboxAlerts(); on || chosen || inFile() {
		t.Fatalf("new store: %v %v", on, chosen)
	}
	for _, want := range []bool{true, false} {
		must(t, s.SetInboxAlerts(&want))
		if on, chosen := s.InboxAlerts(); on != want || !chosen || !inFile() {
			t.Fatalf("set %v: %v %v", want, on, chosen)
		}
		s2, err := Open(dir, key32())
		must(t, err)
		if on, chosen := s2.InboxAlerts(); on != want || !chosen {
			t.Fatalf("set %v, after reopening: %v %v", want, on, chosen)
		}
		if s2.FormatV4() {
			t.Fatal("the setting made the key check v4")
		}
	}
	must(t, s.SetInboxAlerts(nil))
	if on, chosen := s.InboxAlerts(); on || chosen || inFile() {
		t.Fatalf("back to the default: %v %v", on, chosen)
	}
}

// The setting is copied by clone, so a failed save puts it back.
func TestInboxAlertsClone(t *testing.T) {
	dir := t.TempDir()
	s, err := Open(dir, key32())
	must(t, err)
	on := true
	must(t, s.SetInboxAlerts(&on))
	on = false // the store keeps its own copy
	if got, _ := s.InboxAlerts(); !got {
		t.Fatal("the store shares the caller's bool")
	}
	c := s.st.clone()
	*s.st.Notify.Inbox = false
	if !*c.Notify.Inbox {
		t.Fatal("clone shares the setting")
	}
	*s.st.Notify.Inbox = true

	s.path = filepath.Join(dir, "missing", stateFile) // saves now fail
	if err := s.SetInboxAlerts(&on); err == nil {
		t.Fatal("save didn't fail")
	}
	if got, chosen := s.InboxAlerts(); !got || !chosen {
		t.Fatal("off shown although it wasn't saved")
	}
	if err := s.SetInboxAlerts(nil); err == nil {
		t.Fatal("save didn't fail")
	}
	if _, chosen := s.InboxAlerts(); !chosen {
		t.Fatal("default shown although it wasn't saved")
	}
}

// The release with MAC6 (v0.1.3) opens a file with the setting (its MACs
// verify over what it parses), and what it writes back opens here, without
// the setting and with everything else kept.
func TestV6ReleaseReadsNotifyFile(t *testing.T) {
	dir := t.TempDir()
	s := canaried(t, dir)
	must(t, s.SetAlertWebhook(testWebhook))
	_, err := s.CreateToken("agent", []string{"ns"}, PermRead, nil)
	must(t, err)
	must(t, s.SetTokenSelfUpgrade("agent", true))
	on := true
	must(t, s.SetInboxAlerts(&on))
	path := filepath.Join(dir, stateFile)
	data, _ := os.ReadFile(path)
	for _, f := range []string{`"notify"`, `"mac7"`, `"self_upgrade"`, `"mac6"`, `"mac5"`, `"mac4"`, `"mac3"`, `"mac2"`} {
		if !strings.Contains(string(data), f) {
			t.Fatalf("no %s in the file", f)
		}
	}
	var st state
	must(t, json.Unmarshal(data, &st))
	// What the release with MAC6 parses: everything but notify and MAC7.
	v6 := mac6Release(st)
	k, _ := newStore(dir, key32())
	legacy := v6.legacyView()
	if !hmacEqual(v6.MAC, macOf(k.macKey, &legacy)) {
		t.Fatal("mac would not verify in the v6 release")
	}
	v2 := v6.v2View()
	if !hmacEqual(v6.MAC2, macOf(k.mac2Key, &v2)) {
		t.Fatal("mac2 would not verify in the v6 release")
	}
	v3 := v6.v3View()
	if !hmacEqual(v6.MAC3, macOf(k.mac3Key, &v3)) {
		t.Fatal("mac3 would not verify in the v6 release")
	}
	v4 := v6.v4View()
	if !hmacEqual(v6.MAC4, macOf(k.mac4Key, &v4)) {
		t.Fatal("mac4 would not verify in the v6 release")
	}
	v5 := v6.v5View()
	if !hmacEqual(v6.MAC5, macOf(k.mac5Key, &v5)) {
		t.Fatal("mac5 would not verify in the v6 release")
	}
	if !checkMAC6(k, v6) {
		t.Fatal("mac6 would not verify in the v6 release")
	}
	// The v6 release saves the same thing back.
	b, _ := json.MarshalIndent(&v6, "", "  ")
	if strings.Contains(string(b), `"notify"`) || strings.Contains(string(b), `"mac7"`) {
		t.Fatal("the v6 release's view still has the setting")
	}
	os.WriteFile(path, b, 0o600)
	s2, err := Open(dir, key32())
	if err != nil {
		t.Fatalf("open after the v6 release wrote it: %v", err)
	}
	if on, chosen := s2.InboxAlerts(); on || chosen {
		t.Fatal("the setting survived a rewrite by the v6 release")
	}
	if tok, ok := tokenNamedT(s2, "agent"); !ok || !tok.SelfUpgrade {
		t.Fatal("self-upgrade was lost")
	}
	if u, _, _ := s2.AlertWebhook(); u != testWebhook {
		t.Fatal("the webhook was lost")
	}
	if !s2.FormatV4() {
		t.Fatal("the v4 fields were lost")
	}
}

// The setting is covered by MAC7.
func TestNotifyIntegrity(t *testing.T) {
	dir := t.TempDir()
	s := canaried(t, dir)
	_, err := s.CreateToken("agent", []string{"ns"}, PermRead, nil)
	must(t, err)
	must(t, s.SetTokenSelfUpgrade("agent", true))
	on := true
	must(t, s.SetInboxAlerts(&on))
	path := filepath.Join(dir, stateFile)
	data, _ := os.ReadFile(path)

	// The same setting, MAC'd in another file under the same master key.
	otherDir := t.TempDir()
	other, _ := Open(otherDir, key32())
	must(t, other.SetInboxAlerts(&on))
	var otherRaw map[string]any
	otherData, _ := os.ReadFile(filepath.Join(otherDir, stateFile))
	must(t, json.Unmarshal(otherData, &otherRaw))

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
	notify := func(raw map[string]any) map[string]any { return raw["notify"].(map[string]any) }
	try("unchanged", func(map[string]any) {}, nil)
	try("turned off, mac7 kept", func(raw map[string]any) { notify(raw)["inbox"] = false }, ErrIntegrity)
	try("choice removed, mac7 kept", func(raw map[string]any) { delete(notify(raw), "inbox") }, ErrIntegrity)
	try("notify dropped, mac7 kept", func(raw map[string]any) { delete(raw, "notify") }, ErrIntegrity)
	try("mac7 dropped", func(raw map[string]any) { delete(raw, "mac7") }, ErrIntegrity)
	try("mac7 wrong", func(raw map[string]any) { raw["mac7"] = make([]byte, 32) }, ErrIntegrity)
	try("mac7 from another file", func(raw map[string]any) { raw["mac7"] = otherRaw["mac7"] }, ErrIntegrity)
	try("mac6 dropped", func(raw map[string]any) { delete(raw, "mac6") }, ErrIntegrity)
	// Added to a file without it: as it would be after both were stripped.
	try("turned off, without mac7", func(raw map[string]any) {
		delete(raw, "mac7")
		notify(raw)["inbox"] = false
	}, ErrIntegrity)
	// Both dropped is what the release before writes: it opens, with no
	// choice made (the server then uses KEYDROP_ALERT_INBOX), and
	// everything else as it was.
	s2 := try("both dropped", func(raw map[string]any) { delete(raw, "notify"); delete(raw, "mac7") }, nil)
	if on, chosen := s2.InboxAlerts(); on || chosen {
		t.Fatalf("both dropped: %v %v", on, chosen)
	}
	if tok, _ := tokenNamedT(s2, "agent"); !tok.SelfUpgrade {
		t.Fatal("both dropped: self-upgrade lost")
	}
}
