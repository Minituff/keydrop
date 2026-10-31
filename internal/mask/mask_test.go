package mask

import (
	"bytes"
	"encoding/base64"
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
