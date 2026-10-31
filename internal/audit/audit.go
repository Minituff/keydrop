// Package audit records who did what. It never records secret values.
package audit

import (
	"encoding/json"
	"os"
	"sync"
	"time"
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

// Log appends events to a JSON-lines file and keeps the latest in memory for
// the UI.
type Log struct {
	mu     sync.Mutex
	f      *os.File
	recent []Event
	max    int
}

// Open opens (or creates) path for appending and loads its tail.
func Open(path string) (*Log, error) {
	l := &Log{max: 500}
	if data, err := os.ReadFile(path); err == nil {
		for _, line := range splitLines(data) {
			var e Event
			if json.Unmarshal(line, &e) == nil {
				l.push(e)
			}
		}
	}
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return nil, err
	}
	l.f = f
	return l, nil
}

func splitLines(b []byte) [][]byte {
	var out [][]byte
	start := 0
	for i, c := range b {
		if c == '\n' {
			if i > start {
				out = append(out, b[start:i])
			}
			start = i + 1
		}
	}
	if start < len(b) {
		out = append(out, b[start:])
	}
	return out
}

func (l *Log) push(e Event) {
	l.recent = append(l.recent, e)
	if len(l.recent) > l.max {
		l.recent = l.recent[len(l.recent)-l.max:]
	}
}

// Add records an event. Write errors are ignored: auditing must not take the
// service down, and the event is still kept in memory.
func (l *Log) Add(e Event) {
	if e.Time.IsZero() {
		e.Time = time.Now().UTC()
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	l.push(e)
	if l.f != nil {
		if b, err := json.Marshal(e); err == nil {
			l.f.Write(append(b, '\n'))
		}
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
	if l.f == nil {
		return nil
	}
	return l.f.Close()
}
