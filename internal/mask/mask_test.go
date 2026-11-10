package mask

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"io"
	"math/rand/v2"
	"net/url"
	"regexp"
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
		in := "x fake-abcd-and-more-tail y fake-abcd z fake-abcd"
		if split {
			for i := 0; i < len(in); i++ {
				w.Write([]byte{in[i]})
			}
		} else {
			w.Write([]byte(in))
		}
		w.Flush()
		if got, want := buf.String(), "x [keydrop:long] y [keydrop:short] z [keydrop:short]"; got != want {
			t.Fatalf("split=%v: got %q want %q", split, got, want)
		}
	}
}

// Secrets that overlap without one being a prefix of the other: every byte
// of either occurrence must be masked, at any chunk split.
func TestMaskPartialOverlap(t *testing.T) {
	var m Masker
	m.Add("A", []byte("abcd1234"))
	m.Add("B", []byte("1234SECRETTAIL"))
	cases := map[string]string{
		"abcd1234SECRETTAIL":       "[keydrop:A,B]",
		"x abcd1234SECRETTAIL y":   "x [keydrop:A,B] y",
		"1234SECRETTAIL abcd1234":  "[keydrop:B] [keydrop:A]",
		"abcd1234SECRETTAILabcd12": "[keydrop:A,B]abcd12",
		"abcd1234SECRET":           "[keydrop:A]SECRET",
	}
	for in, want := range cases {
		for chunk := 1; chunk <= len(in); chunk++ {
			var buf bytes.Buffer
			w := m.Writer(&buf)
			for i := 0; i < len(in); i += chunk {
				w.Write([]byte(in[i:min(i+chunk, len(in))]))
			}
			w.Flush()
			if got := buf.String(); got != want {
				t.Fatalf("%q in chunks of %d: got %q want %q", in, chunk, got, want)
			}
			for _, s := range []string{"SECRETTAIL", "1234SEC"} {
				if strings.Contains(buf.String(), s) {
					t.Fatalf("%q in chunks of %d leaked %q: %q", in, chunk, s, buf.String())
				}
			}
		}
	}
}

// A chain of overlapping occurrences that never ends must not be held in
// memory forever, and must still be masked.
func TestMaskEndlessOverlapIsBounded(t *testing.T) {
	var m Masker
	m.Add("k", []byte("ABABAB"))
	var buf bytes.Buffer
	w := m.Writer(&buf)
	chunk := bytes.Repeat([]byte("AB"), 1024)
	for i := 0; i < 200; i++ {
		w.Write(chunk)
	}
	if len(w.buf) > 2*maxHeld {
		t.Fatalf("holding %d bytes", len(w.buf))
	}
	w.Flush()
	if strings.Contains(buf.String(), "AB") {
		t.Fatalf("leaked: %q", buf.String()[:100])
	}
}

// fakeSecrets returns n distinct secret-looking values.
func fakeSecrets(n int) [][]byte {
	var out [][]byte
	for i := 0; i < n; i++ {
		out = append(out, []byte(fmt.Sprintf("fake-%03d-%x", i, sha256.Sum256([]byte{byte(i), byte(i >> 8)}))[:40]))
	}
	return out
}

// benchInput is ordinary-looking output: log lines with base64-ish noise,
// and no secrets.
func benchInput() []byte {
	var b bytes.Buffer
	for i := 0; b.Len() < 1<<20; i++ {
		fmt.Fprintf(&b, "2026-01-02T03:04:05Z level=info msg=\"request done\" id=%x path=/api/v1/items/%d status=200 dur=%dms\n",
			sha256.Sum256([]byte{byte(i), byte(i >> 8), byte(i >> 16)}), i, i%977)
	}
	return b.Bytes()
}

func benchmarkMask(b *testing.B, n int) {
	var m Masker
	for i, s := range fakeSecrets(n) {
		m.Add(fmt.Sprintf("S%d", i), s)
	}
	in := benchInput()
	b.SetBytes(int64(len(in)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		w := m.Writer(io.Discard)
		for off := 0; off < len(in); off += 4096 {
			w.Write(in[off:min(off+4096, len(in))])
		}
		w.Flush()
	}
}

func BenchmarkMask1(b *testing.B)   { benchmarkMask(b, 1) }
func BenchmarkMask10(b *testing.B)  { benchmarkMask(b, 10) }
func BenchmarkMask100(b *testing.B) { benchmarkMask(b, 100) }

// Random secrets over a small alphabet (so they overlap a lot) against a
// plain reference: the bytes outside every occurrence pass through, and
// each run of overlapping occurrences becomes one placeholder, however the
// input is split.
func TestMaskMatchesReference(t *testing.T) {
	rng := rand.New(rand.NewPCG(1, 2))
	word := func(n int) []byte {
		b := make([]byte, n)
		for i := range b {
			b[i] = "abc"[rng.IntN(3)]
		}
		return b
	}
	for round := 0; round < 300; round++ {
		var m Masker
		var secrets [][]byte
		for k := 0; k < 1+rng.IntN(4); k++ {
			s := word(4 + rng.IntN(5))
			secrets = append(secrets, s)
			m.Add(fmt.Sprintf("S%d", k), s)
		}
		checkReference(t, rng, &m, secrets, word(rng.IntN(60)))
	}
}

// checkReference checks m's output for in against a plain reference: the
// bytes outside every occurrence of a pattern pass through, each run of
// overlapping occurrences becomes one placeholder, and the result is the
// same for several random splits into writes. It returns the output.
func checkReference(t *testing.T, rng *rand.Rand, m *Masker, secrets [][]byte, in []byte) string {
	t.Helper()
	covered := make([]bool, len(in))
	for _, p := range m.patterns {
		for i := 0; i+len(p.match) <= len(in); i++ {
			if bytes.HasPrefix(in[i:], p.match) {
				for j := i; j < i+len(p.match); j++ {
					covered[j] = true
				}
			}
		}
	}
	whole := m.String(string(in))
	// Strip placeholders: what's left must be exactly the uncovered bytes.
	var visible []byte
	for i, c := range in {
		if !covered[i] {
			visible = append(visible, c)
		}
	}
	stripped := placeholderRE.ReplaceAllString(whole, "")
	if stripped != string(visible) {
		t.Fatalf("secrets %q input %q: got %q, visible should be %q", secrets, in, whole, visible)
	}
	for try := 0; try < 5; try++ {
		var buf bytes.Buffer
		w := m.Writer(&buf)
		for i := 0; i < len(in); {
			n := 1 + rng.IntN(6)
			if try == 4 {
				n = 1 + rng.IntN(100)
			}
			w.Write(in[i:min(i+n, len(in))])
			i += n
		}
		w.Flush()
		if buf.String() != whole {
			t.Fatalf("secrets %q input %q: split gave %q, whole %q", secrets, in, buf.String(), whole)
		}
	}
	return whole
}

var placeholderRE = regexp.MustCompile(`\[keydrop:[^\]]*\]`)

// wrapBase64 encodes b as base64 wrapped at width with nl, the way
// coreutils base64 (76), openssl and PEM (64) and MIME (76, CRLF) do.
func wrapBase64(b []byte, width int, nl string) string {
	enc := base64.StdEncoding.EncodeToString(b)
	var lines []string
	for len(enc) > width {
		lines = append(lines, enc[:width])
		enc = enc[width:]
	}
	return strings.Join(append(lines, enc), nl) + nl
}

// Secrets in line-wrapped base64, wherever the line breaks fall: the
// randomised reference check with wrapped encodings in the input (secrets
// over a small alphabet, so they and their encodings overlap a lot), and
// no run of the secret's encoding left visible.
func TestMaskWrappedBase64MatchesReference(t *testing.T) {
	rng := rand.New(rand.NewPCG(3, 4))
	word := func(n int, alphabet string) []byte {
		b := make([]byte, n)
		for i := range b {
			b[i] = alphabet[rng.IntN(len(alphabet))]
		}
		return b
	}
	for round := 0; round < 300; round++ {
		var m Masker
		var secrets [][]byte
		alphabet := "abc"
		if round%2 == 1 {
			alphabet = "abcdefghijklmnopqrstuvwxyz0123456789/+=-_!@#$%^&*()"
		}
		for k := 0; k < 1+rng.IntN(3); k++ {
			s := word(9+rng.IntN(100), alphabet)
			secrets = append(secrets, s)
			m.Add(fmt.Sprintf("S%d", k), s)
		}
		s := secrets[rng.IntN(len(secrets))]
		data := append(append(word(rng.IntN(150), alphabet), s...), word(rng.IntN(40), alphabet)...)
		width := []int{64, 76}[rng.IntN(2)]
		nl := []string{"\n", "\r\n"}[rng.IntN(2)]
		in := string(word(rng.IntN(20), alphabet)) + "\n" + wrapBase64(data, width, nl) + string(word(rng.IntN(20), alphabet))
		out := checkReference(t, rng, &m, secrets, []byte(in))
		if alphabet == "abc" {
			continue // the data around it encodes to the same runs
		}
		// What's left of the secret's encoding is at most a few characters
		// at each edge: no 8 characters in a row survive.
		flat := strings.NewReplacer("\r", "", "\n", "").Replace(placeholderRE.ReplaceAllString(out, "|"))
		for offset := 0; offset < 3; offset++ {
			core := string(base64Core(base64.StdEncoding, s, offset))
			for i := 0; i+8 <= len(core); i++ {
				if strings.Contains(flat, core[i:i+8]) {
					t.Fatalf("round %d (width %d): %q of the secret's encoding left visible in %q", round, width, core[i:i+8], out)
				}
			}
		}
	}
}

// Real tools' wrapped output: base64 at 76 and 64 columns, and MIME's CRLF,
// with the secret starting at every column.
func TestMaskWrappedBase64EveryColumn(t *testing.T) {
	secret := []byte("fake-api-key-0123456789abcdef-ghijklmnop-0123456789abcdef-qrstuvwxyz")
	var m Masker
	m.Add("k", secret)
	for _, width := range []int{64, 76} {
		for _, nl := range []string{"\n", "\r\n"} {
			for lead := 0; lead < 3*width; lead++ {
				data := append(bytes.Repeat([]byte{'.'}, lead), secret...)
				out := m.String(wrapBase64(append(data, "tail"...), width, nl))
				flat := strings.NewReplacer("\r", "", "\n", "").Replace(strings.ReplaceAll(out, "[keydrop:k]", "|"))
				if !strings.Contains(out, "[keydrop:k]") {
					t.Fatalf("width %d lead %d: not masked: %q", width, lead, out)
				}
				for offset := 0; offset < 3; offset++ {
					core := string(base64Core(base64.StdEncoding, secret, offset))
					for i := 0; i+8 <= len(core); i++ {
						if strings.Contains(flat, core[i:i+8]) {
							t.Fatalf("width %d lead %d: %q left visible in %q", width, lead, core[i:i+8], out)
						}
					}
				}
			}
		}
	}
}

// A line that ends in the first few characters of a secret's encoding
// isn't held back waiting for the next line.
func TestMaskWrappedDoesntHoldLines(t *testing.T) {
	secret := []byte("fake-api-key-0123456789abcdef")
	var m Masker
	m.Add("k", secret)
	core := base64Core(base64.StdEncoding, secret, 0)
	for n := 1; n < wrapMinLead; n++ {
		var buf bytes.Buffer
		w := m.Writer(&buf)
		line := "data: " + string(core[:n]) + "\n"
		w.Write([]byte(line))
		if buf.String() != line {
			t.Fatalf("%d characters: held back, wrote %q", n, buf.String())
		}
	}
}

// Percent-encoding as other tools write it: lower-case hex, and the
// different sets of characters encoders leave alone.
func TestMaskURLEncodings(t *testing.T) {
	secret := "fake/s3cr3t+val~ue!'()* with=&?:@,;$#"
	var m Masker
	m.Add("k", []byte(secret))
	pyQuote := func(s, safe string) string { // urllib.parse.quote
		return string(percentEncode([]byte(s), "-_.~"+safe, false, upperHex))
	}
	for name, enc := range map[string]string{
		"QueryEscape":            url.QueryEscape(secret),
		"PathEscape":             url.PathEscape(secret),
		"lower-case QueryEscape": regexp.MustCompile(`%[0-9A-F]{2}`).ReplaceAllStringFunc(url.QueryEscape(secret), strings.ToLower),
		"Python quote":           pyQuote(secret, "/"),
		"Python quote safe=''":   pyQuote(secret, ""),
		"encodeURIComponent":     "fake%2Fs3cr3t%2Bval~ue!'()*%20with%3D%26%3F%3A%40%2C%3B%24%23",
		"encodeURI":              "fake/s3cr3t+val~ue!'()*%20with=&?:@,;$#",
		"URLSearchParams":        "fake%2Fs3cr3t%2Bval%7Eue%21%27%28%29*+with%3D%26%3F%3A%40%2C%3B%24%23",
		"maximal, lower":         strings.ToLower(string(percentEncode([]byte(secret), "", false, upperHex))),
	} {
		out := m.String("GET /x?token=" + enc + " HTTP/1.1")
		if out != "GET /x?token=[keydrop:k] HTTP/1.1" {
			t.Errorf("%s: %q", name, out)
		}
	}
}
