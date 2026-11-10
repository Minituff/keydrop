package server

import (
	"fmt"
	"net/http/httptest"
	"strings"
	"testing"
)

// Keys idle past their window are dropped even when they left events out,
// so cycling addresses can't grow the map without bound, and their count
// still reaches the log.
func TestNoisyKeysPruned(t *testing.T) {
	h := newHarness(t)
	c := h.clock()
	from := func(ip string) {
		r := httptest.NewRequest("POST", "/api/v1/pair", nil)
		r.RemoteAddr = ip + ":1234"
		h.srv.noisyEvent(r, "unknown", "api.badtoken", "", "")
	}
	// Two requests from one address: one logged, one left out.
	from("10.0.0.1")
	from("10.0.0.1")
	if k := h.srv.noisy.byKey[sourceGroup("10.0.0.1")+" api.badtoken"]; k == nil || k.suppressed != 1 {
		t.Fatalf("second request not counted: %+v", k)
	}
	// Fill the map with idle keys that each left one event out, as many
	// addresses doing the same would.
	h.srv.noisyMu.Lock()
	for i := range maxNoisyKeys {
		h.srv.noisy.byKey[fmt.Sprintf("2001:db8:%x:: api.badtoken", i)] = &noisyKey{last: c.now(), suppressed: 1}
	}
	h.srv.noisyMu.Unlock()
	c.add(2 * noisyPerKey)
	from("192.168.1.50")

	h.srv.noisyMu.Lock()
	left := len(h.srv.noisy.byKey)
	h.srv.noisyMu.Unlock()
	if left != 1 {
		t.Fatalf("%d keys kept after pruning, want only the new one", left)
	}
	ev := h.srv.audit.Recent(1)[0]
	want := fmt.Sprintf("+%d other", maxNoisyKeys+1)
	if ev.IP != "192.168.1.50" || !strings.HasPrefix(ev.Detail, want) {
		t.Fatalf("left-out count lost: %+v", ev)
	}
}
