package main

import (
	"bytes"
	"encoding/base64"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/minituff/keydrop/internal/server"
	"github.com/minituff/keydrop/internal/store"
)

// The data commands, end to end through the command functions: a
// downgraded (older-format) directory stops the server until upgrade-data
// is run, which keeps the certificate and the data; both commands can be
// run twice.
func TestUpgradeDowngradeData(t *testing.T) {
	dir := t.TempDir()
	key := bytes.Repeat([]byte{3}, 32)
	t.Setenv("KEYDROP_DATA_DIR", dir)
	t.Setenv("KEYDROP_MASTER_KEY", base64.StdEncoding.EncodeToString(key))
	t.Setenv("KEYDROP_MASTER_KEY_FILE", "")
	// If the server got past opening the data it would fail here, rather
	// than listen.
	t.Setenv("KEYDROP_TLS", "not-a-mode")

	st, err := store.Open(dir, key)
	if err != nil {
		t.Fatal(err)
	}
	st.PutValue("lab", "FAKE_TOKEN", []byte("fake-value-123"), nil)
	_, fp, err := server.LoadOrCreateSelfSigned(dir, nil, st)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		if err := cmdDowngradeData(nil); err != nil {
			t.Fatalf("downgrade-data #%d: %v", i+1, err)
		}
	}
	before, _ := os.ReadFile(filepath.Join(dir, "keydrop.json"))
	if err := cmdServer(nil); !errors.Is(err, store.ErrNeedsUpgrade) {
		t.Fatalf("server on old-format data: %v", err)
	}
	if after, _ := os.ReadFile(filepath.Join(dir, "keydrop.json")); !bytes.Equal(before, after) {
		t.Fatal("server changed old-format data")
	}
	if err := cmdRotateTLS(nil); err == nil {
		t.Fatal("rotate-tls on old-format data")
	}
	for i := 0; i < 2; i++ {
		if err := cmdUpgradeData(nil); err != nil {
			t.Fatalf("upgrade-data #%d: %v", i+1, err)
		}
	}
	st2, err := store.Open(dir, key)
	if err != nil {
		t.Fatalf("open after upgrade-data: %v", err)
	}
	if v, _, _ := st2.Reveal("lab", "FAKE_TOKEN", "test"); string(v) != "fake-value-123" {
		t.Fatal("value changed")
	}
	if _, fp2, err := server.LoadOrCreateSelfSigned(dir, nil, st2); err != nil || fp2 != fp {
		t.Fatalf("certificate after upgrade-data: %v (pin %s, was %s)", err, fp2, fp)
	}
	if err := cmdServer(nil); err == nil || errors.Is(err, store.ErrNeedsUpgrade) {
		t.Fatalf("server after upgrade-data should get as far as the TLS mode: %v", err)
	}

	// upgrade-data never creates a data directory.
	t.Setenv("KEYDROP_DATA_DIR", filepath.Join(t.TempDir(), "typo"))
	if err := cmdUpgradeData(nil); err == nil {
		t.Fatal("upgrade-data on an empty directory")
	}
}
