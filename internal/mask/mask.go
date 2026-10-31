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
	"sort"
	"sync"
)

// MinLength is the shortest value that gets masked. Masking a 1–3 character
// value would mangle ordinary output.
const MinLength = 4

type pattern struct {
	match []byte
	repl  []byte
}

// Masker holds the patterns for a set of secrets. Share one between stdout
// and stderr writers.
type Masker struct {
	patterns []pattern
}

// Add registers value under label. It also masks common encodings of the
// value (base64, URL-encoded), which is how secrets often reappear in debug
// output such as Basic auth headers. It returns false if value is too short
// to mask.
func (m *Masker) Add(label string, value []byte) bool {
	if len(value) < MinLength {
		return false
	}
	repl := []byte("[keydrop:" + label + "]")
	variants := [][]byte{
		value,
		[]byte(base64.StdEncoding.EncodeToString(value)),
		[]byte(base64.RawStdEncoding.EncodeToString(value)),
		[]byte(base64.RawURLEncoding.EncodeToString(value)),
		[]byte(url.QueryEscape(string(value))),
		[]byte(url.PathEscape(string(value))),
	}
	for _, v := range variants {
		if len(v) < MinLength || m.has(v) {
			continue
		}
		m.patterns = append(m.patterns, pattern{match: v, repl: repl})
	}
	// Longest first, so a longer match wins over one of its substrings.
	sort.SliceStable(m.patterns, func(i, j int) bool { return len(m.patterns[i].match) > len(m.patterns[j].match) })
	return true
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

func (w *Writer) drain(final bool) error {
	var out []byte
	i := 0
scan:
	for i < len(w.buf) {
		rest := w.buf[i:]
		for _, p := range w.m.patterns {
			if bytes.HasPrefix(rest, p.match) {
				out = append(out, p.repl...)
				i += len(p.match)
				continue scan
			}
		}
		if !final {
			for _, p := range w.m.patterns {
				if len(rest) < len(p.match) && bytes.HasPrefix(p.match, rest) {
					break scan // could be the start of a secret: wait for more
				}
			}
		}
		out = append(out, w.buf[i])
		i++
	}
	w.buf = append(w.buf[:0], w.buf[i:]...)
	if len(out) == 0 {
		return nil
	}
	_, err := w.w.Write(out)
	return err
}
