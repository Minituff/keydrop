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
}

// Add registers value under label. It also masks common encodings of the
// value (base64, URL-encoded), which is how secrets often reappear in debug
// output such as Basic auth headers. It returns false if value, or value
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
		[]byte(url.QueryEscape(string(value))),
		[]byte(url.PathEscape(string(value))),
	}
	for _, enc := range []*base64.Encoding{base64.StdEncoding, base64.URLEncoding} {
		for offset := 0; offset < 3; offset++ {
			variants = append(variants, base64Core(enc, value, offset))
		}
	}
	for _, v := range variants {
		if len(v) < MinLength || m.has(v) {
			continue
		}
		m.patterns = append(m.patterns, pattern{match: v, label: label})
	}
	// Longest first, so a longer match wins over one of its substrings.
	sort.SliceStable(m.patterns, func(i, j int) bool { return len(m.patterns[i].match) > len(m.patterns[j].match) })
	m.index()
	return masked
}

func key2(b []byte) int { return int(b[0])<<8 | int(b[1]) }

// index rebuilds the first-two-bytes index.
func (m *Masker) index() {
	m.starts = make([]int32, 1<<16+1)
	for _, p := range m.patterns {
		m.starts[key2(p.match)+1]++
		m.first[p.match[0]] = true
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

func (m *Masker) has(v []byte) bool {
	for _, p := range m.patterns {
		if bytes.Equal(p.match, v) {
			return true
		}
	}
	return false
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
