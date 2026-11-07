package auth

import (
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestPassword(t *testing.T) {
	h, err := HashPassword("correct horse battery")
	if err != nil {
		t.Fatal(err)
	}
	if !CheckPassword(h, "correct horse battery") || CheckPassword(h, "wrong") {
		t.Fatal("password check wrong")
	}
}

// RFC 6238 appendix B test vector (SHA-1, seed "12345678901234567890").
func TestTOTPVector(t *testing.T) {
	seed := []byte("12345678901234567890")
	if got := totpCode(seed, 59/30); got != "287082" {
		t.Fatalf("got %s", got)
	}
	if _, ok := CheckTOTP(seed, "287082", time.Unix(59, 0)); !ok {
		t.Fatal("valid code rejected")
	}
	if _, ok := CheckTOTP(seed, "287082", time.Unix(59+120, 0)); ok {
		t.Fatal("stale code accepted")
	}
}

func TestLimiter(t *testing.T) {
	l := NewLimiter()
	now := time.Now()
	for i := 0; i < 5; i++ {
		if _, err := l.Try("a", false, now); err != nil {
			t.Fatal("locked too early")
		}
	}
	if _, err := l.Try("a", false, now); err == nil {
		t.Fatal("not locked after 5 failures")
	}
	if _, err := l.Try("b", false, now); err != nil {
		t.Fatal("other client locked")
	}
	if _, err := l.Try("a", false, now.Add(16*time.Minute)); err != nil {
		t.Fatal("lock didn't expire")
	}
}

// Attempts are reserved before checking, so parallel requests can't all
// pass the check before any failure is recorded.
func TestLimiterConcurrent(t *testing.T) {
	l := NewLimiter()
	now := time.Now()
	var wg sync.WaitGroup
	var allowed atomic.Int32
	for i := 0; i < 60; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := l.Try("a", false, now); err == nil {
				allowed.Add(1)
			}
		}()
	}
	wg.Wait()
	if allowed.Load() != 5 {
		t.Fatalf("%d parallel attempts allowed, want 5", allowed.Load())
	}
}

// Many addresses can exhaust the global limit, but a trusted client is
// limited only by its own failures, and success gives its attempt back.
func TestLimiterGlobalAndExempt(t *testing.T) {
	l := NewLimiter()
	now := time.Now()
	for i := 0; i < 20; i++ {
		if _, err := l.Try(fmt.Sprint("attacker-", i), false, now); err != nil {
			t.Fatalf("attempt %d locked", i)
		}
	}
	if _, err := l.Try("newcomer", false, now); err == nil {
		t.Fatal("global limit not applied")
	}
	a, err := l.Try("device:owner", true, now)
	if err != nil {
		t.Fatal("trusted client locked out by others' failures")
	}
	a.Succeed()
	for i := 0; i < 5; i++ {
		if _, err := l.Try("device:owner", true, now); err != nil {
			t.Fatalf("success didn't clear the trusted client's count (try %d)", i)
		}
	}
	if _, err := l.Try("device:owner", true, now); err == nil {
		t.Fatal("trusted client not limited by its own failures")
	}
}
