package audit

import (
	"encoding/json"
	"fmt"
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

// A flood of unauthenticated events can't rotate authenticated ones off
// disk or out of the UI's list: they have their own file and list.
func TestNoiseCantEvictAuthenticated(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.jsonl")
	l, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	l.MaxBytes = 4096
	l.Add(Event{Actor: "token:box", Action: "secret.read", Target: "lab/FAKE"})
	for i := 0; i < 5000; i++ {
		l.Add(Event{Actor: "unknown", Action: "api.badtoken", IP: "10.0.0.9", Unauthenticated: true})
	}
	l.Add(Event{Actor: "admin", Action: "login"})
	main, _ := os.ReadFile(path)
	if !strings.Contains(string(main), "secret.read") || strings.Contains(string(main), "badtoken") {
		t.Fatalf("main log: %s", main)
	}
	if _, err := os.Stat(path + ".1"); err == nil {
		t.Fatal("noise rotated the main log")
	}
	noise, _ := os.ReadFile(NoisePath(path))
	if !strings.Contains(string(noise), "badtoken") {
		t.Fatal("unauthenticated events not in their own file")
	}
	if _, err := os.Stat(NoisePath(path) + ".2"); err == nil {
		t.Fatal("unauthenticated log kept more than one old copy")
	}
	got := l.Recent(1000)
	if got[0].Action != "login" || got[1].Action != "api.badtoken" || got[len(got)-1].Action != "secret.read" {
		t.Fatalf("recent: first %s, %s, last %s (%d)", got[0].Action, got[1].Action, got[len(got)-1].Action, len(got))
	}
	l.Close()
	// After a restart both lists come back, each marked as it was.
	l2, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer l2.Close()
	got = l2.Recent(1000)
	var reads, unauth int
	for _, e := range got {
		if e.Action == "secret.read" {
			reads++
		}
		if e.Unauthenticated {
			unauth++
		}
	}
	if reads != 1 || unauth == 0 || got[0].Action != "login" {
		t.Fatalf("after restart: %d reads, %d unauthenticated, newest %s", reads, unauth, got[0].Action)
	}
}

// The main log keeps five rotated copies.
func TestMainLogGenerations(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	l, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	l.MaxBytes = 1024
	for i := 0; i < 400; i++ {
		l.Add(Event{Actor: "admin", Action: "secret.reveal", Target: fmt.Sprintf("lab/S%03d", i)})
	}
	l.Close()
	for i := 1; i <= MainGenerations; i++ {
		if _, err := os.Stat(fmt.Sprintf("%s.%d", path, i)); err != nil {
			t.Fatalf("generation %d: %v", i, err)
		}
	}
	if _, err := os.Stat(fmt.Sprintf("%s.%d", path, MainGenerations+1)); err == nil {
		t.Fatal("kept too many generations")
	}
	newest, _ := os.ReadFile(path)
	oldest, _ := os.ReadFile(fmt.Sprintf("%s.%d", path, MainGenerations))
	if !strings.Contains(string(newest), "S399") || strings.Contains(string(oldest), "S399") {
		t.Fatal("generations out of order")
	}
}

// Text (an agent's flag reason and link) is kept whole up to MaxText.
func TestTextKeptToMaxText(t *testing.T) {
	l, err := Open(filepath.Join(t.TempDir(), "audit.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	whole := strings.Repeat("r", 500) + " <https://example.com/" + strings.Repeat("l", 470) + ">"
	l.Add(Event{Actor: "token:x", Action: "secret.flag", Text: whole})
	l.Add(Event{Actor: "token:x", Action: "secret.flag", Text: strings.Repeat("x", 1<<20)})
	got := l.Recent(2)
	var kept, clipped bool
	for _, e := range got {
		kept = kept || e.Text == whole
		clipped = clipped || (len(e.Text) <= MaxText && strings.HasSuffix(e.Text, "…"))
	}
	if !kept || !clipped {
		t.Fatalf("text kept %v, long text clipped %v", kept, clipped)
	}
}

// Record, used before showing a value, waits for the disk and fails if it
// can't; Add, used for everything else, doesn't wait.
func TestRecordSyncs(t *testing.T) {
	l, err := Open(filepath.Join(t.TempDir(), "audit.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	syncs, fail := 0, false
	syncFile = func(f *os.File) error {
		syncs++
		if fail {
			return fmt.Errorf("disk gone")
		}
		return f.Sync()
	}
	defer func() { syncFile = (*os.File).Sync }()

	l.Add(Event{Actor: "unknown", Action: "api.badtoken"})
	l.Add(Event{Actor: "unknown", Action: "api.badtoken", Unauthenticated: true})
	if syncs != 0 {
		t.Fatalf("Add synced %d times", syncs)
	}
	if err := l.Record(Event{Actor: "token:x", Action: "secret.read"}); err != nil || syncs != 1 {
		t.Fatalf("Record: %v, %d syncs", err, syncs)
	}
	fail = true
	if err := l.Record(Event{Actor: "token:x", Action: "secret.read"}); err == nil {
		t.Fatal("Record succeeded although the sync failed")
	}
	fail = false
	if err := l.Record(Event{Actor: "token:x", Action: "secret.read"}); err != nil {
		t.Fatalf("after the disk came back: %v", err)
	}
}
