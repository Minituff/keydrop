package store

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const testWebhook = "https://hooks.example.com/api/webhooks/123/fake-webhook-token"

func TestAlertWebhook(t *testing.T) {
	dir := t.TempDir()
	s, err := Open(dir, key32())
	must(t, err)
	if u, _, err := s.AlertWebhook(); u != "" || err != nil {
		t.Fatalf("new store: %q %v", u, err)
	}
	must(t, s.SetAlertWebhook(testWebhook))
	data, _ := os.ReadFile(filepath.Join(dir, stateFile))
	if strings.Contains(string(data), "fake-webhook-token") || strings.Contains(string(data), "hooks.example.com") {
		t.Fatal("the webhook is in the file in plaintext")
	}
	s2, err := Open(dir, key32())
	must(t, err)
	if u, at, err := s2.AlertWebhook(); u != testWebhook || at.IsZero() || err != nil {
		t.Fatalf("after reopening: %q %v %v", u, at, err)
	}
	if s2.FormatV4() {
		t.Fatal("the webhook alone made the key check v4")
	}
	if err := s2.SetAlertWebhook(strings.Repeat("x", MaxWebhookLen+1)); err == nil {
		t.Fatal("an over-long webhook was stored")
	}
	must(t, s2.SetAlertWebhook(""))
	data, _ = os.ReadFile(filepath.Join(dir, stateFile))
	if strings.Contains(string(data), `"alerts"`) || strings.Contains(string(data), `"mac5"`) {
		t.Fatal("removing the webhook left it in the file")
	}
}

// The release with MAC4 opens a file with the webhook set (its MACs verify
// over what it parses), and what it writes back opens here, without the
// webhook.
func TestV4ReleaseReadsAlertsFile(t *testing.T) {
	for _, withV4 := range []bool{false, true} {
		dir := t.TempDir()
		var s *Store
		if withV4 {
			s = canaried(t, dir)
		} else {
			s = grouped(t, dir)
		}
		must(t, s.SetAlertWebhook(testWebhook))
		path := filepath.Join(dir, stateFile)
		data, _ := os.ReadFile(path)
		for _, f := range []string{`"alerts"`, `"mac5"`} {
			if !strings.Contains(string(data), f) {
				t.Fatalf("no %s in the file", f)
			}
		}
		var st state
		must(t, json.Unmarshal(data, &st))
		// What the release with MAC4 parses: everything but alerts and MAC5.
		v4 := st.v4View()
		v4.MAC, v4.MAC2, v4.MAC3, v4.MAC4 = st.MAC, st.MAC2, st.MAC3, st.MAC4
		k, _ := newStore(dir, key32())
		legacy := v4.legacyView()
		if !hmacEqual(v4.MAC, macOf(k.macKey, &legacy)) {
			t.Fatal("mac would not verify in the v4 release")
		}
		v2 := v4.v2View()
		if (st.MAC2 != nil) && !hmacEqual(v4.MAC2, macOf(k.mac2Key, &v2)) {
			t.Fatal("mac2 would not verify in the v4 release")
		}
		v3 := v4.v3View()
		if (st.MAC3 != nil) && !hmacEqual(v4.MAC3, macOf(k.mac3Key, &v3)) {
			t.Fatal("mac3 would not verify in the v4 release")
		}
		check := v4
		check.MAC, check.MAC2, check.MAC3, check.MAC4 = nil, nil, nil, nil
		if withV4 != (st.MAC4 != nil) {
			t.Fatalf("mac4 present: %v", st.MAC4 != nil)
		}
		if st.MAC4 != nil && !hmacEqual(v4.MAC4, macOf(k.mac4Key, &check)) {
			t.Fatal("mac4 would not verify in the v4 release")
		}
		// The v4 release saves the same thing back.
		b, _ := json.MarshalIndent(&v4, "", "  ")
		os.WriteFile(path, b, 0o600)
		s2, err := Open(dir, key32())
		if err != nil {
			t.Fatalf("open after the v4 release wrote it: %v", err)
		}
		if u, _, _ := s2.AlertWebhook(); u != "" {
			t.Fatal("the webhook survived a rewrite by the v4 release")
		}
		if withV4 && !s2.FormatV4() {
			t.Fatal("the v4 fields were lost")
		}
	}
}

// The webhook is covered by MAC5.
func TestAlertFieldsIntegrity(t *testing.T) {
	dir := t.TempDir()
	s := canaried(t, dir)
	must(t, s.SetAlertWebhook(testWebhook))
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
	alerts := func(raw map[string]any) map[string]any { return raw["alerts"].(map[string]any) }
	try("unchanged", func(map[string]any) {}, nil)
	try("set_at edited", func(raw map[string]any) { alerts(raw)["set_at"] = "2020-01-01T00:00:00Z" }, ErrIntegrity)
	try("mac5 dropped", func(raw map[string]any) { delete(raw, "mac5") }, ErrIntegrity)
	try("alerts dropped, mac5 kept", func(raw map[string]any) { delete(raw, "alerts") }, ErrIntegrity)
	other, _ := Open(t.TempDir(), key32())
	must(t, other.SetAlertWebhook("https://attacker.example.com/hook"))
	try("webhook swapped from another file", func(raw map[string]any) {
		alerts(raw)["webhook"] = other.st.Alerts.Webhook
	}, ErrIntegrity)
	// Both dropped is what the release before writes: it opens, without
	// the webhook (the server then uses KEYDROP_ALERT_WEBHOOK).
	try("both dropped", func(raw map[string]any) { delete(raw, "alerts"); delete(raw, "mac5") }, nil)
}
