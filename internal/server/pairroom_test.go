package server

import (
	"fmt"
	"net/http"
	"testing"
	"time"
)

// Many addresses with one request each can't shut pairing off: when no
// group is busier than the newcomer's, the oldest waiting request makes
// way.
func TestPairingFullOfSingles(t *testing.T) {
	h := newHarness(t)
	h.setup()
	for i := range maxPairings {
		if code, _ := h.apiFrom(fmt.Sprintf("10.0.5.%d", i), "POST", "/api/v1/pair", "", "", map[string]string{}); code != http.StatusCreated {
			t.Fatalf("filling %d: %d", i, code)
		}
	}
	if code, _ := h.apiFrom("10.0.6.1", "POST", "/api/v1/pair", "", "", map[string]string{}); code != http.StatusCreated {
		t.Fatalf("newcomer refused when every address has one request: %d", code)
	}
	h.srv.pairMu.Lock()
	n := len(h.srv.pairings)
	h.srv.pairMu.Unlock()
	if n != maxPairings {
		t.Fatalf("%d waiting, want %d", n, maxPairings)
	}
}

// Which request makes way when the list is full.
func TestPairingRoomRules(t *testing.T) {
	h := newHarness(t)
	base := time.Now()
	type req struct {
		ip       string
		approved bool
	}
	// fill puts reqs in the list, each a second newer than the one before.
	fill := func(reqs []req) {
		h.srv.pairings = map[string]*pairing{}
		for i, r := range reqs {
			id := fmt.Sprintf("p%02d", i)
			h.srv.pairings[id] = &pairing{ID: id, IP: r.ip, Created: base.Add(time.Duration(i) * time.Second), approved: r.approved}
		}
	}
	gone := func(t *testing.T, ok bool, want string) {
		t.Helper()
		if !ok {
			t.Fatal("refused")
		}
		if len(h.srv.pairings) != maxPairings-1 {
			t.Fatalf("%d left, want %d", len(h.srv.pairings), maxPairings-1)
		}
		if _, still := h.srv.pairings[want]; still {
			t.Fatalf("%s should have made way", want)
		}
	}
	singles := func() []req {
		var r []req
		for i := range maxPairings {
			r = append(r, req{ip: fmt.Sprintf("10.0.7.%d", i)})
		}
		return r
	}
	h.srv.pairMu.Lock()
	defer h.srv.pairMu.Unlock()

	t.Run("oldest unapproved when no group is busier", func(t *testing.T) {
		r := singles()
		r[0].approved = true
		fill(r)
		gone(t, h.srv.makePairingRoomLocked("10.0.8.1"), "p01")
	})
	t.Run("busiest group first", func(t *testing.T) {
		r := singles()
		for i := 10; i < 10+maxPairingsPerIP; i++ {
			r[i].ip = "10.0.9.9"
		}
		fill(r)
		gone(t, h.srv.makePairingRoomLocked("10.0.8.1"), "p10")
	})
	t.Run("never an approved one", func(t *testing.T) {
		r := singles()
		for i := range r {
			r[i].approved = true
		}
		fill(r)
		if h.srv.makePairingRoomLocked("10.0.8.1") || len(h.srv.pairings) != maxPairings {
			t.Fatal("an approved request made way")
		}
	})
	t.Run("per-address cap still applies", func(t *testing.T) {
		r := singles()
		for i := range maxPairingsPerIP {
			r[i].ip = "10.0.8.1"
		}
		fill(r)
		if h.srv.makePairingRoomLocked("10.0.8.1") || len(h.srv.pairings) != maxPairings {
			t.Fatal("an address past its cap got in")
		}
	})
}
