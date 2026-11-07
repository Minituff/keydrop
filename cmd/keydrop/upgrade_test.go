package main

import "testing"

func TestSumFor(t *testing.T) {
	const a = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	const b = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	sums := a + "  keydrop-linux-amd64\n" + b + " *keydrop-darwin-arm64\nnot-hex  keydrop-linux-arm64\n"
	for name, want := range map[string]string{
		"keydrop-linux-amd64":  a,
		"keydrop-darwin-arm64": b,  // binary-mode line
		"keydrop-linux-arm64":  "", // malformed hash
		"keydrop-linux":        "", // no partial matches
	} {
		if got := sumFor(sums, name); got != want {
			t.Errorf("%s: %q, want %q", name, got, want)
		}
	}
}
