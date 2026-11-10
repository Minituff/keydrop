// Package mask replaces secret values in a byte stream with a placeholder,
// so a command's output can't leak a secret into an agent's transcript.
//
// It works on streams: if output ends partway through something that could
// be the start of a secret, those bytes are held back until the next write
// (or Flush) shows whether it's a match. Nothing else is delayed.
package mask

import (
	"bytes"
	"encoding/base64"
	"io"
	"net/url"
	"slices"
	"sort"
	"strings"
	"sync"
)

// MinLength is the shortest value that gets masked. Masking a 1–3 character
// value would mangle ordinary output.
const MinLength = 4

// maxHeld bounds how much output a Writer holds back. Only a chain of
// overlapping occurrences that keeps growing (the same secret repeated, say)
// reaches it; the chain is then replaced up to there, and the rest of it is
// still masked as it arrives.
const maxHeld = 64 << 10

type pattern struct {
	match []byte
	label string
}

// Masker holds the patterns for a set of secrets. Share one between stdout
// and stderr writers.
type Masker struct {
	patterns []pattern
	// The patterns are indexed by their first two bytes (every pattern has
	// at least MinLength), so each output position looks at the few that
	// could start there instead of all of them: starts[k]..starts[k+1] in
	// order are the pattern indexes for key k, longest first.
	starts []int32
	order  []int32
	first  [256]bool // some pattern starts with this byte
	// keys has a bit set for each first two bytes some pattern starts
	// with: 8 KiB, so most positions are ruled out without touching the
	// much larger starts table.
	keys [1 << 16 / 64]uint64
	seen map[string]bool
}

// Add registers value under label. It also masks common encodings of the
// value (base64, line-wrapped base64, URL-encoded), which is how secrets
// often reappear in debug output such as Basic auth headers. It returns
// false if value, or value
// without its surrounding whitespace, is too short to mask, so the caller
// can warn.
func (m *Masker) Add(label string, value []byte) bool {
	if len(value) < MinLength {
		return false
	}
	// A value stored with a trailing newline usually reaches the output
	// without it, as in curl -H "Authorization: $KEY".
	masked := true
	if t := bytes.TrimSpace(value); len(t) < len(value) {
		masked = m.Add(label, t)
	}
	variants := [][]byte{
		value,
		[]byte(base64.StdEncoding.EncodeToString(value)),
		[]byte(base64.RawStdEncoding.EncodeToString(value)),
		[]byte(base64.URLEncoding.EncodeToString(value)),
		[]byte(base64.RawURLEncoding.EncodeToString(value)),
	}
	variants = append(variants, urlEncodings(value)...)
	for _, enc := range []*base64.Encoding{base64.StdEncoding, base64.URLEncoding} {
		for offset := 0; offset < 3; offset++ {
			core := base64Core(enc, value, offset)
			variants = append(variants, core)
			if enc == base64.StdEncoding && len(value) <= maxWrapped {
				variants = append(variants, wrapped(core)...)
			}
		}
	}
	if m.seen == nil {
		m.seen = map[string]bool{}
	}
	for _, v := range variants {
		if len(v) < MinLength || m.seen[string(v)] {
			continue
		}
		m.seen[string(v)] = true
		m.patterns = append(m.patterns, pattern{match: v, label: label})
	}
	// Longest first, so a longer match wins over one of its substrings.
	sort.SliceStable(m.patterns, func(i, j int) bool { return len(m.patterns[i].match) > len(m.patterns[j].match) })
	m.index()
	return masked
}

// urlEncodings are value percent-encoded the ways common tools do it.
// Encoders differ in which characters they leave alone, in how they write
// a space and in the case of the hex digits, and any of them can print a
// secret in a URL or a form body: Go's QueryEscape and PathEscape,
// Python's quote (leaves "/"), JS's encodeURIComponent (leaves "!'()*"),
// encodeURI (leaves the reserved characters too: the minimal escaping) and
// URLSearchParams, and an encoder that escapes all but letters and digits
// (the maximal one), each with upper- and lower-case hex. Ones equal to
// value itself, or to each other, are dropped by Add.
func urlEncodings(value []byte) [][]byte {
	s := string(value)
	out := [][]byte{[]byte(url.QueryEscape(s)), []byte(url.PathEscape(s))}
	for _, enc := range []struct {
		safe string
		plus bool // a space is "+"
	}{
		{"-_.~", false},                 // RFC 3986 unreserved (PHP rawurlencode, strict encoders)
		{"-_.~/", false},                // Python urllib.parse.quote
		{"-_.~!'()*", false},            // JS encodeURIComponent
		{"-_.~!'()*;,/?:@&=+$#", false}, // JS encodeURI: the minimal escaping
		{"-_.*", true},                  // HTML forms, JS URLSearchParams
		{"", false},                     // maximal: only letters and digits stay
	} {
		out = append(out, percentEncode(value, enc.safe, enc.plus, upperHex), percentEncode(value, enc.safe, enc.plus, lowerHex))
	}
	for _, v := range out[:2] {
		out = append(out, lowerEscapes(v))
	}
	return out
}

const (
	upperHex = "0123456789ABCDEF"
	lowerHex = "0123456789abcdef"
)

// percentEncode escapes every byte of v except ASCII letters, digits and
// the characters in safe, as %XX with the given hex digits. With plus a
// space is written "+".
func percentEncode(v []byte, safe string, plus bool, hex string) []byte {
	out := make([]byte, 0, len(v)*3)
	for _, c := range v {
		switch {
		case 'a' <= c && c <= 'z' || 'A' <= c && c <= 'Z' || '0' <= c && c <= '9' || c < 0x80 && strings.IndexByte(safe, c) >= 0:
			out = append(out, c)
		case c == ' ' && plus:
			out = append(out, '+')
		default:
			out = append(out, '%', hex[c>>4], hex[c&15])
		}
	}
	return out
}

// lowerEscapes is v with the hex digits of its %XX escapes in lower case.
func lowerEscapes(v []byte) []byte {
	out := slices.Clone(v)
	for i := 0; i+2 < len(out); i++ {
		if out[i] == '%' {
			out[i+1] = toLowerHex(out[i+1])
			out[i+2] = toLowerHex(out[i+2])
			i += 2
		}
	}
	return out
}

func toLowerHex(c byte) byte {
	if 'A' <= c && c <= 'F' {
		return c + 'a' - 'A'
	}
	return c
}

// wrapWidths are the line lengths base64 is usually wrapped at: 76
// (coreutils base64, MIME) and 64 (PEM, openssl base64).
var wrapWidths = []int{64, 76}

// maxWrapped is the longest value whose line-wrapped base64 is masked.
// Each first-break position is a pattern as long as the encoding (some
// 280 for each of three alignments), so they take over a thousand times
// the value's size: about 5 MB at this size, which covers an RSA-4096
// private key in PEM. Longer values are masked unwrapped only.
const maxWrapped = 4 << 10

// wrapMinLead is how many of a core's characters must come before the
// first line break for the wrapped form to start at the core's start.
// Otherwise every line that ended in the first character or two of an
// encoding would be held back until more output came, which would delay
// interactive output. With fewer, the pattern starts wrapMinLead
// characters into the core, after the break, so at most wrapMinLead
// characters of the encoding stay visible, like the edge characters
// base64Core already leaves. (Starting all of those at one place, not
// just after the break, keeps the number of distinct pattern starts, and
// so the cost per output byte, low.)
const wrapMinLead = 4

// wrapped is core as it appears in line-wrapped base64: a break ("\n" or
// "\r\n") after its first j characters, for every j a line width allows,
// and every width characters after that. Where the core starts in the
// encoded text isn't known, so each first break is a pattern. They're
// plain byte strings like every other pattern, so the Writer's promises
// (same output however the stream is split, bounded hold-back) hold for
// them unchanged.
func wrapped(core []byte) [][]byte {
	if len(core) < 3*wrapMinLead {
		return nil // short enough to mask anywhere it isn't split
	}
	var out [][]byte
	for _, width := range wrapWidths {
		for _, nl := range []string{"\n", "\r\n"} {
			for j := 1; j < len(core) && j <= width; j++ {
				start := 0
				if j < wrapMinLead {
					start = wrapMinLead
				}
				var b []byte
				prev := start
				for k := j; k < len(core); k += width {
					if k > start {
						b = append(b, core[prev:k]...)
						b = append(b, nl...)
						prev = k
					}
				}
				out = append(out, append(b, core[prev:]...))
			}
		}
	}
	return out
}

func key2(b []byte) int { return int(b[0])<<8 | int(b[1]) }

// index rebuilds the first-two-bytes index.
func (m *Masker) index() {
	m.starts = make([]int32, 1<<16+1)
	for _, p := range m.patterns {
		k := key2(p.match)
		m.starts[k+1]++
		m.first[p.match[0]] = true
		m.keys[k>>6] |= 1 << (k & 63)
	}
	for k := 1; k < len(m.starts); k++ {
		m.starts[k] += m.starts[k-1]
	}
	m.order = make([]int32, len(m.patterns))
	next := slices.Clone(m.starts[:1<<16])
	for i, p := range m.patterns { // stays longest first within a key
		k := key2(p.match)
		m.order[next[k]] = int32(i)
		next[k]++
	}
}

// at looks at the output from one position, rest. It returns the longest
// pattern that rest starts with, if any. Unless final, it first reports
// maybe if rest is shorter than a pattern it's the start of, so more output
// could still make a (longer) match here.
func (m *Masker) at(rest []byte, final bool) (match *pattern, maybe bool) {
	if !m.first[rest[0]] {
		return nil, false
	}
	if len(rest) == 1 {
		return nil, !final // every pattern is longer than one byte
	}
	k := key2(rest)
	if m.keys[k>>6]&(1<<(k&63)) == 0 {
		return nil, false
	}
	for _, i := range m.order[m.starts[k]:m.starts[k+1]] {
		p := &m.patterns[i]
		if len(rest) < len(p.match) {
			if !final && bytes.HasPrefix(p.match, rest) {
				return nil, true
			}
		} else if bytes.HasPrefix(rest, p.match) {
			return p, false // longest first: nothing longer can follow
		}
	}
	return nil, false
}

// base64Core is the part of the base64 encoding of value that doesn't
// depend on its neighbours, when value starts offset bytes into a 3-byte
// group. Basic auth encodes "user:secret" in one piece, so the secret
// starts at offset len(user)+1 mod 3, and its plain encoding only appears
// when that's 0. The characters that mix in bits of the bytes before or
// after are left out, so this matches whatever surrounds the secret.
func base64Core(enc *base64.Encoding, value []byte, offset int) []byte {
	buf := make([]byte, offset+len(value))
	copy(buf[offset:], value)
	full := len(buf) / 3 * 3
	out := []byte(enc.WithPadding(base64.NoPadding).EncodeToString(buf[:full]))
	// A trailing partial group: only the characters made entirely of its
	// own bits are fixed (one for one byte, two for two).
	if rest := len(buf) - full; rest > 0 {
		tail := enc.WithPadding(base64.NoPadding).EncodeToString(buf[full:])
		out = append(out, tail[:rest*8/6]...)
	}
	// Leading characters that include bits of the bytes before: one byte
	// before touches 2 characters, two bytes touch 3.
	skip := (offset*8 + 5) / 6
	if skip > len(out) {
		return nil
	}
	return out[skip:]
}

// String masks a complete string in one go.
func (m *Masker) String(s string) string {
	var b bytes.Buffer
	w := m.Writer(&b)
	io.WriteString(w, s)
	w.Flush()
	return b.String()
}

// Writer returns a masking writer in front of w. Call Flush when the stream
// ends.
func (m *Masker) Writer(w io.Writer) *Writer { return &Writer{m: m, w: w} }

// Writer is a masking io.Writer.
type Writer struct {
	m   *Masker
	w   io.Writer
	mu  sync.Mutex
	buf []byte
	// covered is how many bytes at the start of buf belong to an
	// occurrence whose placeholder is already written.
	covered int
}

// Write masks p and writes what's safe to write now. It always reports
// len(p) on success, since held-back bytes are still owned by the writer.
func (w *Writer) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.buf = append(w.buf, p...)
	if err := w.drain(false); err != nil {
		return 0, err
	}
	return len(p), nil
}

// Flush writes everything held back.
func (w *Writer) Flush() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.drain(true)
}

// span is a stretch of output covered by one or more overlapping
// occurrences of secrets.
type span struct {
	a, b    int
	labels  []string
	carried bool // continues one already replaced in an earlier write
}

func (sp *span) placeholder() []byte {
	if sp.carried {
		return nil
	}
	return []byte("[keydrop:" + strings.Join(sp.labels, ",") + "]")
}

// drain writes out what's decided. Every byte of every occurrence of a
// pattern is masked: occurrences that overlap are merged into one span and
// replaced by one placeholder naming each secret involved. Output is held
// back from the first position that could still turn out to start an
// occurrence, and from the start of a span that reaches past it, since a
// later occurrence could extend that span.
func (w *Writer) drain(final bool) error {
	buf := w.buf
	n := len(buf)
	hold := n
	var spans []span
	if w.covered > 0 {
		spans = append(spans, span{a: 0, b: w.covered, carried: true})
	}
	for i := 0; i < n; i++ {
		p, maybe := w.m.at(buf[i:], final)
		if maybe {
			hold = i
			break
		}
		if p == nil {
			continue
		}
		end := i + len(p.match)
		// Spans are found in order of start, so a new occurrence can only
		// overlap the last one.
		if k := len(spans) - 1; k >= 0 && i < spans[k].b {
			if end > spans[k].b {
				spans[k].b = end
				if !slices.Contains(spans[k].labels, p.label) {
					spans[k].labels = append(spans[k].labels, p.label)
				}
			}
			continue
		}
		spans = append(spans, span{a: i, b: end, labels: []string{p.label}})
	}

	cut := hold // everything before cut is written now
	covered := 0
	var out []byte
	pos := 0
	for k := range spans {
		sp := &spans[k]
		if sp.a >= cut {
			break
		}
		if sp.b > cut {
			if n-sp.a <= maxHeld {
				cut = sp.a // wait and see how far it reaches
				break
			}
			// Held too long: replace it up to cut now, and remember that
			// the bytes after cut are part of it.
			out = append(out, buf[pos:sp.a]...)
			out = append(out, sp.placeholder()...)
			covered = sp.b - cut
			pos = cut
			break
		}
		out = append(out, buf[pos:sp.a]...)
		out = append(out, sp.placeholder()...)
		pos = sp.b
	}
	if pos < cut {
		out = append(out, buf[pos:cut]...)
	}
	if cut > 0 {
		w.buf = append(w.buf[:0], buf[cut:]...)
		w.covered = covered
	}
	if len(out) == 0 {
		return nil
	}
	_, err := w.w.Write(out)
	return err
}
