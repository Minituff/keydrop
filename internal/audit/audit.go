// Package audit records who did what. It never records secret values.
package audit

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
	"time"
	"unicode/utf8"
)

// Event is one audit record.
type Event struct {
	Time   time.Time `json:"time"`
	Actor  string    `json:"actor"` // "admin", "token:<name>" or "system"
	Action string    `json:"action"`
	Target string    `json:"target,omitempty"`
	Detail string    `json:"detail,omitempty"`
	// Text is longer free text an agent wrote (a flag's reason and link),
	// kept so the record shows what was said. Capped at MaxText.
	Text string `json:"text,omitempty"`
	IP   string `json:"ip,omitempty"`
	// Unauthenticated marks an event a request without a credential caused
	// (a bad token, a pairing request). Those go to their own file.
	Unauthenticated bool `json:"unauthenticated,omitempty"`
}

const (
	// MaxField caps each text field, so a request can't write a megabyte
	// into the log (a long ?purpose=, say).
	MaxField = 200
	// MaxText caps Text: enough for a flag's reason and link in full.
	MaxText = 1100
	// DefaultMaxBytes is the size at which each file is rotated.
	DefaultMaxBytes = 10 << 20
	// MainGenerations is how many rotated copies of the main log are kept
	// (<path>.1 … <path>.5), NoiseGenerations of the unauthenticated one.
	MainGenerations  = 5
	NoiseGenerations = 1
	// tailBytes is how much of each file is read at start to fill the
	// UI's recent list. The files themselves are never read whole.
	tailBytes = 512 << 10
	// keep is how many recent events of each kind are kept in memory.
	keep = 500
)

// Log appends events to JSON-lines files and keeps the latest in memory for
// the UI. Events that need a credential (a secret read, an admin change)
// go to the main file; events anyone on the network can cause go to a
// separate file (NoisePath) with its own rotation and its own in-memory
// list, so a flood of them can't rotate or crowd out the ones that matter.
type Log struct {
	mu sync.Mutex
	// MaxBytes is the size at which each file is rotated.
	MaxBytes    int64
	main, noise *file
}

type file struct {
	path   string
	gens   int
	f      *os.File
	size   int64
	recent []Event
}

// NoisePath is where the unauthenticated events for the main log at path
// go: audit.jsonl → audit-unauth.jsonl.
func NoisePath(path string) string {
	if strings.HasSuffix(path, ".jsonl") {
		return strings.TrimSuffix(path, ".jsonl") + "-unauth.jsonl"
	}
	return path + "-unauth"
}

// Open opens (or creates) the main log at path and the unauthenticated one
// beside it, and loads their tails.
func Open(path string) (*Log, error) {
	l := &Log{MaxBytes: DefaultMaxBytes,
		main:  &file{path: path, gens: MainGenerations},
		noise: &file{path: NoisePath(path), gens: NoiseGenerations}}
	for _, f := range []*file{l.main, l.noise} {
		if err := f.loadTail(f == l.noise); err != nil {
			return nil, err
		}
		if err := f.open(); err != nil {
			l.Close()
			return nil, err
		}
	}
	return l, nil
}

func (lf *file) loadTail(noise bool) error {
	f, err := os.Open(lf.path)
	if os.IsNotExist(err) {
		return nil
	} else if err != nil {
		return err
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return err
	}
	off := max(fi.Size()-tailBytes, 0)
	data, err := io.ReadAll(io.NewSectionReader(f, off, fi.Size()-off))
	if err != nil {
		return err
	}
	if off > 0 {
		// Started mid-line: skip to the first whole one.
		if i := bytes.IndexByte(data, '\n'); i >= 0 {
			data = data[i+1:]
		} else {
			data = nil
		}
	}
	for _, line := range bytes.Split(data, []byte{'\n'}) {
		var e Event
		if len(line) > 0 && json.Unmarshal(line, &e) == nil {
			e.Unauthenticated = noise
			lf.push(e)
		}
	}
	return nil
}

func (lf *file) open() error {
	f, err := os.OpenFile(lf.path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	fi, err := f.Stat()
	if err != nil {
		f.Close()
		return err
	}
	lf.f, lf.size = f, fi.Size()
	return nil
}

// rotate shifts <path>.1 … to .2 …, dropping the oldest, moves the file to
// <path>.1 and starts a new one.
func (lf *file) rotate() {
	lf.f.Close()
	lf.f = nil
	for i := lf.gens - 1; i >= 1; i-- {
		_ = os.Rename(fmt.Sprintf("%s.%d", lf.path, i), fmt.Sprintf("%s.%d", lf.path, i+1))
	}
	_ = os.Rename(lf.path, lf.path+".1")
	_ = lf.open()
}

func (lf *file) push(e Event) {
	lf.recent = append(lf.recent, e)
	if len(lf.recent) > keep {
		lf.recent = lf.recent[len(lf.recent)-keep:]
	}
}

func (lf *file) write(e Event, maxBytes int64) {
	if lf.f == nil {
		return
	}
	b, err := json.Marshal(e)
	if err != nil {
		return
	}
	if maxBytes > 0 && lf.size+int64(len(b))+1 > maxBytes && lf.size > 0 {
		lf.rotate()
		if lf.f == nil {
			return
		}
	}
	if n, err := lf.f.Write(append(b, '\n')); err == nil {
		lf.size += int64(n)
	}
}

// clip shortens s to at most MaxField bytes, on a rune boundary.
func clip(s string) string { return clipTo(s, MaxField) }

func clipTo(s string, n int) string {
	if len(s) <= n {
		return s
	}
	cut := n - len("…")
	for cut > 0 && !utf8.RuneStart(s[cut]) {
		cut--
	}
	return s[:cut] + "…"
}

// Add records an event. Write errors are ignored: auditing must not take the
// service down, and the event is still kept in memory. An event with
// Unauthenticated set goes to the unauthenticated log.
func (l *Log) Add(e Event) {
	if e.Time.IsZero() {
		e.Time = time.Now().UTC()
	}
	e.Actor, e.Action, e.Target, e.Detail, e.IP = clip(e.Actor), clip(e.Action), clip(e.Target), clip(e.Detail), clip(e.IP)
	e.Text = clipTo(e.Text, MaxText)
	l.mu.Lock()
	defer l.mu.Unlock()
	lf := l.main
	if e.Unauthenticated {
		lf = l.noise
	}
	lf.push(e)
	lf.write(e, l.MaxBytes)
}

// Recent returns up to n events from both logs, newest first.
func (l *Log) Recent(n int) []Event {
	l.mu.Lock()
	defer l.mu.Unlock()
	out := make([]Event, 0, n)
	a, b := l.main.recent, l.noise.recent
	i, j := len(a)-1, len(b)-1
	for len(out) < n && (i >= 0 || j >= 0) {
		if j < 0 || (i >= 0 && !a[i].Time.Before(b[j].Time)) {
			out = append(out, a[i])
			i--
		} else {
			out = append(out, b[j])
			j--
		}
	}
	return out
}

// Close closes the files.
func (l *Log) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	var first error
	for _, lf := range []*file{l.main, l.noise} {
		if lf.f != nil {
			if err := lf.f.Close(); err != nil && first == nil {
				first = err
			}
			lf.f = nil
		}
	}
	return first
}
