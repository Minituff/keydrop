package server

import (
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// breakAudit makes the audit log unwritable until the returned func runs: a
// directory where the file should be stands in for a full disk.
func breakAudit(t *testing.T, h *harness) (restore func()) {
	t.Helper()
	path := filepath.Join(h.dir, "audit.jsonl")
	if err := h.srv.audit.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		t.Fatal(err)
	}
	if err := os.Mkdir(path, 0o700); err != nil {
		t.Fatal(err)
	}
	return func() {
		if err := os.Remove(path); err != nil {
			t.Fatal(err)
		}
	}
}

// Every view of a secret is logged, so a read that can't be logged doesn't
// happen, and a canary fails exactly as an ordinary secret does.
func TestRevealFailsWithoutAnAuditRecord(t *testing.T) {
	h := newHarness(t)
	h.setup()
	h.st.PutValue("lab", "REAL", []byte("fake-real-value"), nil)
	h.st.PutValue("lab", "DECOY", []byte("fake-decoy-value"), nil)
	if err := h.st.SetCanary("lab", "DECOY", true); err != nil {
		t.Fatal(err)
	}
	h.form("/secrets", url.Values{"namespace": {"lab"}, "name": {"PLAIN"}, "value": {"plain-setting"}, "kind": {"variable"}})
	tok := h.createToken("bot", "lab")
	restore := breakAudit(t, h)

	code, _, raw := h.api("POST", "/api/v1/secrets/lab/REAL/reveal", tok, nil)
	if code != http.StatusInternalServerError || strings.Contains(string(raw), "fake-real") {
		t.Fatalf("reveal: %d %s", code, raw)
	}
	dcode, _, draw := h.api("POST", "/api/v1/secrets/lab/DECOY/reveal", tok, nil)
	if dcode != code || string(draw) != string(raw) {
		t.Fatalf("a canary answers differently: %d %s / %d %s", dcode, draw, code, raw)
	}
	// A variable's reads aren't logged, so it doesn't depend on the log.
	if code, m, _ := h.api("POST", "/api/v1/secrets/lab/PLAIN/reveal", tok, nil); code != 200 || m["value"] != "plain-setting" {
		t.Fatalf("variable: %d %v", code, m)
	}
	// The admin's view fails the same way.
	code, page := h.form("/secret/lab/REAL/reveal", url.Values{})
	if code != http.StatusInternalServerError || strings.Contains(page, "fake-real") {
		t.Fatalf("web reveal: %d", code)
	}

	// Logging comes back by itself, with no restart.
	restore()
	if code, m, _ := h.api("POST", "/api/v1/secrets/lab/REAL/reveal", tok, nil); code != 200 || m["value"] != "fake-real-value" {
		t.Fatalf("after the disk came back: %d %v", code, m)
	}
	b, err := os.ReadFile(filepath.Join(h.dir, "audit.jsonl"))
	if err != nil || !strings.Contains(string(b), "secret.read") {
		t.Fatalf("no record on disk: %v", err)
	}
}
