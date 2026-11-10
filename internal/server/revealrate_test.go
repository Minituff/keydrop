package server

import (
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/minituff/keydrop/internal/store"
)

// Reveals and acks share a per-token limit. Past it: 429 and no value,
// for secrets and variables alike; other tokens are unaffected, and an
// ungranted namespace is still a 404.
func TestRevealRateLimit(t *testing.T) {
	h := newHarness(t)
	h.setup()
	h.st.PutValue("lab", "REAL", []byte("fake-real-value"), nil)
	h.st.PutValue("other", "HIDDEN", []byte("fake-hidden-value"), nil)
	h.form("/secrets", url.Values{"namespace": {"lab"}, "name": {"PLAIN"}, "value": {"plain-setting"}, "kind": {"variable"}})
	alice, _ := h.st.CreateToken("alice", []string{"lab"}, store.PermRead, nil)
	bob, _ := h.st.CreateToken("bob", []string{"lab"}, store.PermRead, nil)

	// Use up all but two of alice's hour.
	if !h.srv.reveals.allowN("alice", revealsPerHour-2, h.srv.now()) {
		t.Fatal("couldn't fill the limit")
	}
	if code, m, _ := h.api("POST", "/api/v1/secrets/lab/REAL/reveal", alice, nil); code != http.StatusOK || m["value"] != "fake-real-value" {
		t.Fatalf("within the limit: %d %v", code, m)
	}
	if code, _, _ := h.api("POST", "/api/v1/secrets/lab/REAL/ack", alice, nil); code != http.StatusOK {
		t.Fatalf("ack within the limit: %d", code)
	}
	for _, p := range []string{"REAL/reveal", "PLAIN/reveal", "REAL/ack"} {
		code, m, raw := h.api("POST", "/api/v1/secrets/lab/"+p, alice, nil)
		if code != http.StatusTooManyRequests || m["value"] != nil || strings.Contains(string(raw), "fake-real") || strings.Contains(string(raw), "plain-setting") {
			t.Fatalf("%s over the limit: %d %s", p, code, raw)
		}
		if !strings.Contains(m["error"].(string), "too many reveals") {
			t.Fatalf("%s: unhelpful message %q", p, m["error"])
		}
	}
	// The namespace check comes first: same 404 as a missing secret.
	if code, _, _ := h.api("POST", "/api/v1/secrets/other/HIDDEN/reveal", alice, nil); code != http.StatusNotFound {
		t.Fatalf("ungranted namespace: %d", code)
	}
	if code, m, _ := h.api("POST", "/api/v1/secrets/lab/REAL/reveal", bob, nil); code != http.StatusOK || m["value"] != "fake-real-value" {
		t.Fatalf("another token: %d %v", code, m)
	}
	n := 0
	for _, e := range h.srv.audit.Recent(1000) {
		if e.Action == "token.ratelimited" {
			n++
			if e.Actor != "token:alice" || e.Unauthenticated {
				t.Fatalf("refusal logged as %+v", e)
			}
		}
	}
	if n != 1 { // three refusals, throttled to one entry a minute
		t.Fatalf("%d token.ratelimited entries, want 1", n)
	}
}

// A token reading in a loop can't push another read out of the Log: past
// its limit, nothing more of it reaches the main log but one throttled line.
func TestRevealFloodKeepsEarlierReads(t *testing.T) {
	h := newHarness(t)
	h.setup()
	h.st.PutValue("lab", "REAL", []byte("fake-real-value"), nil)
	alice, _ := h.st.CreateToken("alice", []string{"lab"}, store.PermRead, nil)
	bob, _ := h.st.CreateToken("bob", []string{"lab"}, store.PermRead, nil)
	if code, _, _ := h.api("POST", "/api/v1/secrets/lab/REAL/reveal", bob, nil); code != http.StatusOK {
		t.Fatalf("bob: %d", code)
	}
	const limit = 50 // the same code path as revealsPerHour, quicker to reach
	h.srv.reveals = newRateLimit(limit, time.Hour)
	ok := 0
	for range 600 { // more than the 500 events the Log keeps in memory
		if code, _, _ := h.api("POST", "/api/v1/secrets/lab/REAL/reveal", alice, nil); code == http.StatusOK {
			ok++
		}
	}
	if ok != limit {
		t.Fatalf("%d reveals allowed, want %d", ok, limit)
	}
	bobRead, aliceReads := false, 0
	for _, e := range h.srv.audit.Recent(1000) {
		switch {
		case e.Action == "secret.read" && e.Actor == "token:bob":
			bobRead = true
		case e.Action == "secret.read" && e.Actor == "token:alice":
			aliceReads++
		}
	}
	if !bobRead || aliceReads != limit {
		t.Fatalf("bob's read kept: %v; alice's reads logged: %d", bobRead, aliceReads)
	}
}
