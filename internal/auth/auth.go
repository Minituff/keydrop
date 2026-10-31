// Package auth has the admin login primitives: password hashing (PBKDF2,
// stdlib only) and TOTP (RFC 6238), plus a simple failed-login limiter.
package auth

import (
	"crypto/hmac"
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base32"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"
)

// OWASP's 2023 recommendation for PBKDF2-HMAC-SHA256.
const pbkdf2Iterations = 600_000

// MinPasswordLength is enforced at setup.
const MinPasswordLength = 12

// HashPassword returns "pbkdf2-sha256$<iter>$<salt>$<hash>".
func HashPassword(pw string) (string, error) {
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	dk, err := pbkdf2.Key(sha256.New, pw, salt, pbkdf2Iterations, 32)
	if err != nil {
		return "", err
	}
	enc := base64.RawStdEncoding
	return fmt.Sprintf("pbkdf2-sha256$%d$%s$%s", pbkdf2Iterations, enc.EncodeToString(salt), enc.EncodeToString(dk)), nil
}

// CheckPassword compares pw against a HashPassword result in constant time.
func CheckPassword(hash, pw string) bool {
	parts := strings.Split(hash, "$")
	if len(parts) != 4 || parts[0] != "pbkdf2-sha256" {
		return false
	}
	iter, err := strconv.Atoi(parts[1])
	if err != nil || iter < 1 {
		return false
	}
	enc := base64.RawStdEncoding
	salt, err1 := enc.DecodeString(parts[2])
	want, err2 := enc.DecodeString(parts[3])
	if err1 != nil || err2 != nil {
		return false
	}
	got, err := pbkdf2.Key(sha256.New, pw, salt, iter, len(want))
	if err != nil {
		return false
	}
	return subtle.ConstantTimeCompare(got, want) == 1
}

// ---- TOTP ----

const totpPeriod = 30

var b32 = base32.StdEncoding.WithPadding(base32.NoPadding)

// NewTOTPSecret returns a random 160-bit seed.
func NewTOTPSecret() []byte {
	b := make([]byte, 20)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return b
}

// TOTPBase32 is the seed in the form authenticator apps accept.
func TOTPBase32(seed []byte) string { return b32.EncodeToString(seed) }

// TOTPURI builds an otpauth:// link. On a phone, tapping it opens the
// authenticator app directly, which is easier than scanning a QR code on the
// same screen.
func TOTPURI(seed []byte, issuer, account string) string {
	v := url.Values{}
	v.Set("secret", TOTPBase32(seed))
	v.Set("issuer", issuer)
	v.Set("algorithm", "SHA1")
	v.Set("digits", "6")
	v.Set("period", strconv.Itoa(totpPeriod))
	return "otpauth://totp/" + url.PathEscape(issuer+":"+account) + "?" + v.Encode()
}

func totpCode(seed []byte, step int64) string {
	var msg [8]byte
	binary.BigEndian.PutUint64(msg[:], uint64(step))
	m := hmac.New(sha1.New, seed)
	m.Write(msg[:])
	sum := m.Sum(nil)
	off := sum[len(sum)-1] & 0x0f
	n := binary.BigEndian.Uint32(sum[off:off+4]) & 0x7fffffff
	return fmt.Sprintf("%06d", n%1_000_000)
}

// Code returns the TOTP code for time t.
func Code(seed []byte, t time.Time) string { return totpCode(seed, t.Unix()/totpPeriod) }

// CheckTOTP accepts the current code or one step either side (clock drift)
// and returns the matching step, so the caller can reject replays.
func CheckTOTP(seed []byte, code string, now time.Time) (int64, bool) {
	code = strings.ReplaceAll(strings.TrimSpace(code), " ", "")
	if len(code) != 6 {
		return 0, false
	}
	cur := now.Unix() / totpPeriod
	for _, step := range []int64{cur - 1, cur, cur + 1} {
		if subtle.ConstantTimeCompare([]byte(totpCode(seed, step)), []byte(code)) == 1 {
			return step, true
		}
	}
	return 0, false
}

// ---- failed-login limiter ----

// ErrLocked is returned while a client (or the whole login) is locked out.
var ErrLocked = errors.New("too many failed attempts, try again later")

// Limiter locks a client out after PerClient failures within Window, and
// locks out everyone after Global failures within Window. The global limit
// is what actually protects a LAN-only app from a distributed guesser.
type Limiter struct {
	PerClient int
	Global    int
	Window    time.Duration

	mu      sync.Mutex
	clients map[string][]time.Time
	global  []time.Time
}

// NewLimiter returns a limiter with sensible defaults.
func NewLimiter() *Limiter {
	return &Limiter{PerClient: 5, Global: 20, Window: 15 * time.Minute, clients: map[string][]time.Time{}}
}

func prune(ts []time.Time, cutoff time.Time) []time.Time {
	i := 0
	for i < len(ts) && ts[i].Before(cutoff) {
		i++
	}
	return ts[i:]
}

// Allow reports whether client may attempt a login now.
func (l *Limiter) Allow(client string, now time.Time) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	cutoff := now.Add(-l.Window)
	l.global = prune(l.global, cutoff)
	l.clients[client] = prune(l.clients[client], cutoff)
	if len(l.global) >= l.Global || len(l.clients[client]) >= l.PerClient {
		return ErrLocked
	}
	return nil
}

// Fail records a failed attempt.
func (l *Limiter) Fail(client string, now time.Time) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.global = append(l.global, now)
	l.clients[client] = append(l.clients[client], now)
}

// Succeed clears a client's failures.
func (l *Limiter) Succeed(client string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	delete(l.clients, client)
}
