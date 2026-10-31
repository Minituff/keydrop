// Package audit records who did what. It never records secret values.
package audit

import (
	"bytes"
	"encoding/json"
	"io"
	"os"
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
	IP     string    `json:"ip,omitempty"`
}

const (
	// MaxField caps each text field, so a request can't write a megabyte
	// into the log (a long ?purpose=, say).
	MaxField = 200
	// DefaultMaxBytes is the size at which the log is rotated to
	// <path>.1, replacing the previous one: at most twice this on disk.
	DefaultMaxBytes = 10 << 20
	// tailBytes is how much of the log is read at start to fill the UI's
	// recent list. The file itself is never read whole.
	tailBytes = 512 << 10
)

// Log appends events to a JSON-lines file and keeps the latest in memory for
// the UI.
type Log struct {
	mu       sync.Mutex
	path     string
	f        *os.File
	size     int64
	MaxBytes int64
	recent   []Event
	max      int
}

// Open opens (or creates) path for appending and loads its tail.
func Open(path string) (*Log, error) {
	l := &Log{path: path, max: 500, MaxBytes: DefaultMaxBytes}
	if err := l.loadTail(); err != nil {
		return nil, err
	}
	if err := l.openFile(); err != nil {
		return nil, err
	}
	return l, nil
}

func (l *Log) loadTail() error {
	f, err := os.Open(l.path)
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
			l.push(e)
		}
	}
	return nil
}

func (l *Log) openFile() error {
	f, err := os.OpenFile(l.path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	fi, err := f.Stat()
	if err != nil {
		f.Close()
		return err
	}
	l.f, l.size = f, fi.Size()
	return nil
}

// rotate moves the log to <path>.1 and starts a new one. Call with l.mu
// held.
func (l *Log) rotate() {
	l.f.Close()
	l.f = nil
	_ = os.Rename(l.path, l.path+".1")
	_ = l.openFile()
}

func (l *Log) push(e Event) {
	l.recent = append(l.recent, e)
	if len(l.recent) > l.max {
		l.recent = l.recent[len(l.recent)-l.max:]
	}
}

// clip shortens s to at most MaxField bytes, on a rune boundary.
func clip(s string) string {
	if len(s) <= MaxField {
		return s
	}
	cut := MaxField - len("…")
	for cut > 0 && !utf8.RuneStart(s[cut]) {
		cut--
	}
	return s[:cut] + "…"
}

// Add records an event. Write errors are ignored: auditing must not take the
// service down, and the event is still kept in memory.
func (l *Log) Add(e Event) {
	if e.Time.IsZero() {
		e.Time = time.Now().UTC()
	}
	e.Actor, e.Action, e.Target, e.Detail, e.IP = clip(e.Actor), clip(e.Action), clip(e.Target), clip(e.Detail), clip(e.IP)
	l.mu.Lock()
	defer l.mu.Unlock()
	l.push(e)
	if l.f == nil {
		return
	}
	b, err := json.Marshal(e)
	if err != nil {
		return
	}
	if l.MaxBytes > 0 && l.size+int64(len(b))+1 > l.MaxBytes && l.size > 0 {
		l.rotate()
		if l.f == nil {
			return
		}
	}
	if n, err := l.f.Write(append(b, '\n')); err == nil {
		l.size += int64(n)
	}
}

// Recent returns up to n events, newest first.
func (l *Log) Recent(n int) []Event {
	l.mu.Lock()
	defer l.mu.Unlock()
	out := make([]Event, 0, n)
	for i := len(l.recent) - 1; i >= 0 && len(out) < n; i-- {
		out = append(out, l.recent[i])
	}
	return out
}

// Close closes the file.
func (l *Log) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.f == nil {
		return nil
	}
	return l.f.Close()
}
