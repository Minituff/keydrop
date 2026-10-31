package audit

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestClipAndRotate(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	l, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	l.MaxBytes = 4096
	l.Add(Event{Actor: "token:x", Action: "secret.read", Detail: strings.Repeat("p", 1<<20)})
	if fi, _ := os.Stat(path); fi.Size() > 1024 {
		t.Fatalf("a long purpose made a %d-byte line", fi.Size())
	}
	for i := 0; i < 200; i++ {
		l.Add(Event{Actor: "unknown", Action: "api.badtoken", IP: "10.0.0.9"})
	}
	l.Close()
	cur, _ := os.Stat(path)
	old, err := os.Stat(path + ".1")
	if err != nil || cur.Size() > 4096 || old.Size() > 4096 {
		t.Fatalf("not rotated: %v", err)
	}
}

func TestOpenReadsOnlyTheTail(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	f, _ := os.Create(path)
	line, _ := json.Marshal(Event{Actor: "admin", Action: "login", Detail: strings.Repeat("d", 150)})
	for i := 0; i < 2*tailBytes/len(line); i++ {
		f.Write(append(line, '\n'))
	}
	f.Close()
	l, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	got := l.Recent(1000)
	if len(got) != 500 || got[0].Action != "login" {
		t.Fatalf("recent: %d", len(got))
	}
}
