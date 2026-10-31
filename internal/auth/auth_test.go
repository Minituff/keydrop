package auth

import (
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
		if l.Allow("a", now) != nil {
			t.Fatal("locked too early")
		}
		l.Fail("a", now)
	}
	if l.Allow("a", now) == nil {
		t.Fatal("not locked after 5 failures")
	}
	if l.Allow("b", now) != nil {
		t.Fatal("other client locked")
	}
	if l.Allow("a", now.Add(16*time.Minute)) != nil {
		t.Fatal("lock didn't expire")
	}
}
