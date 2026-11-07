package qr

import (
	"bytes"
	"strings"
	"testing"
)

// Reference values from the QR code specification (ISO/IEC 18004) tables
// and its worked "HELLO WORLD" 1-M example.

func TestReedSolomon(t *testing.T) {
	data := []byte{32, 91, 11, 120, 209, 114, 220, 77, 67, 64, 236, 17, 236, 17, 236, 17}
	want := []byte{196, 35, 39, 119, 235, 215, 231, 226, 93, 23}
	if got := rsRemainder(data, 10); !bytes.Equal(got, want) {
		t.Fatalf("got %v, want %v", got, want)
	}
}

func TestFormatAndVersionBits(t *testing.T) {
	want := []int{
		0b101010000010010, 0b101000100100101, 0b101111001111100, 0b101101101001011,
		0b100010111111001, 0b100000011001110, 0b100111110010111, 0b100101010100000,
	}
	for m, w := range want {
		if got := formatBits(m); got != w {
			t.Errorf("mask %d: got %015b, want %015b", m, got, w)
		}
	}
	if got := versionBits(7); got != 0b000111110010010100 {
		t.Errorf("version 7: got %018b", got)
	}
}

func TestEncodeShape(t *testing.T) {
	uri := "otpauth://totp/keydrop:admin?algorithm=SHA1&digits=6&issuer=keydrop&period=30&secret=ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
	c, err := Encode(uri)
	if err != nil {
		t.Fatal(err)
	}
	// 120-odd bytes: version 7 or 8 at level M.
	if c.Size < 41 || c.Size > 53 {
		t.Fatalf("unexpected size %d", c.Size)
	}
	// Finder pattern corners are dark, their inner ring light.
	for _, p := range [][2]int{{0, 0}, {c.Size - 7, 0}, {0, c.Size - 7}} {
		if !c.Dark(p[0], p[1]) || c.Dark(p[0]+1, p[1]+1) || !c.Dark(p[0]+3, p[1]+3) {
			t.Fatalf("finder at %v is wrong", p)
		}
	}
	if !c.Dark(8, c.Size-8) {
		t.Fatal("dark module missing")
	}
	svg := c.SVG()
	if !strings.HasPrefix(svg, "<svg") || strings.ContainsAny(svg, "'&") {
		t.Fatalf("bad svg: %.80s", svg)
	}
	if _, err := Encode(strings.Repeat("x", 413)); err != ErrTooLong {
		t.Fatalf("want ErrTooLong, got %v", err)
	}
}
