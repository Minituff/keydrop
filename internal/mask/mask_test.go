package mask

import (
	"bytes"
	"encoding/base64"
	"strings"
	"testing"
)

func TestMaskWholeAndEncoded(t *testing.T) {
	var m Masker
	m.Add("cf", []byte("s3cr3t-value/+="))
	in := "token=s3cr3t-value/+= b64=" + base64.StdEncoding.EncodeToString([]byte("s3cr3t-value/+=")) + " url=s3cr3t-value%2F%2B%3D"
	out := m.String(in)
	if strings.Contains(out, "s3cr3t") || strings.Contains(out, base64.StdEncoding.EncodeToString([]byte("s3cr3t-value/+="))) {
		t.Fatalf("leaked: %q", out)
	}
	if strings.Count(out, "[keydrop:cf]") != 3 {
		t.Fatalf("want 3 masks, got %q", out)
	}
}

// A secret split across writes must still be masked, byte by byte.
func TestMaskSplitAcrossWrites(t *testing.T) {
	var m Masker
	m.Add("k", []byte("ABCDEFGH"))
	var buf bytes.Buffer
	w := m.Writer(&buf)
	for _, c := range []byte("xxABCDEFGHyyABCDEFGzz ABCD") {
		w.Write([]byte{c})
	}
	w.Flush()
	if got, want := buf.String(), "xx[keydrop:k]yyABCDEFGzz ABCD"; got != want {
		t.Fatalf("got %q want %q", got, want)
	}
}

// Output that can't be the start of a secret is passed through at once.
func TestNoNeedlessHolding(t *testing.T) {
	var m Masker
	m.Add("k", []byte("ABCDEFGH"))
	var buf bytes.Buffer
	w := m.Writer(&buf)
	w.Write([]byte("hello\n"))
	if buf.String() != "hello\n" {
		t.Fatalf("held back %q", buf.String())
	}
	w.Write([]byte("AB"))
	if buf.String() != "hello\n" {
		t.Fatalf("should hold a possible prefix, got %q", buf.String())
	}
	w.Flush()
	if buf.String() != "hello\nAB" {
		t.Fatalf("flush lost bytes: %q", buf.String())
	}
}

func TestShortValuesNotMasked(t *testing.T) {
	var m Masker
	if m.Add("x", []byte("ab")) {
		t.Fatal("short value should be refused")
	}
}

// Basic auth encodes "user:secret" as one base64 string, so the secret's
// own base64 only appears when len(user)+1 is a multiple of 3. Every
// alignment must be masked, wherever the secret ends.
func TestMaskBase64AtEveryOffset(t *testing.T) {
	secret := "fake-token-0123456789abcdef"
	for _, user := range []string{"ab", "abc", "abcd", "x", "user", "admin"} {
		for _, tail := range []string{"", "!", "?x", "@host"} {
			var m Masker
			m.Add("k", []byte(secret))
			enc := base64.StdEncoding.EncodeToString([]byte(user + ":" + secret + tail))
			for _, e := range []string{enc, strings.TrimRight(enc, "="),
				base64.RawURLEncoding.EncodeToString([]byte(user + ":" + secret + tail))} {
				out := m.String("Authorization: Basic " + e + "\n")
				if !strings.Contains(out, "[keydrop:k]") {
					t.Fatalf("user %q tail %q: not masked: %q", user, tail, out)
				}
				// What's left visible is the user's part, the tail and a few
				// edge characters, never a run of the secret's encoding.
				left := strings.TrimSuffix(strings.Replace(strings.TrimPrefix(out, "Authorization: Basic "), "[keydrop:k]", "", 1), "\n")
				if max := (len(user)+1)*4/3 + 2 + (len(tail)*4+2)/3 + 4; len(left) > max {
					t.Fatalf("user %q tail %q: %d characters left visible in %q", user, tail, len(left), out)
				}
			}
		}
	}
}

// When one secret is a prefix of another, the longer one must still be
// masked whole, including when it arrives a byte at a time.
func TestMaskPrefixOverlap(t *testing.T) {
	var m Masker
	m.Add("short", []byte("fake-abcd"))
	m.Add("long", []byte("fake-abcd-and-more-tail"))
	for _, split := range []bool{false, true} {
		var buf bytes.Buffer
		w := m.Writer(&buf)
		in := "x fake-abcd-and-more-tail y fake-abcd z"
		if split {
			for i := 0; i < len(in); i++ {
				w.Write([]byte{in[i]})
			}
		} else {
			w.Write([]byte(in))
		}
		w.Flush()
		if got, want := buf.String(), "x [keydrop:long] y [keydrop:short] z"; got != want {
			t.Fatalf("split=%v: got %q want %q", split, got, want)
		}
	}
}
