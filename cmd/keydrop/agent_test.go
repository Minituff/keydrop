package main

import (
	"flag"
	"reflect"
	"strings"
	"testing"
)

func TestParseEnvFile(t *testing.T) {
	in := `# not attached (blank line follows)

# Cloudflare DNS token
# scoped to one zone
CLOUDFLARE_API_TOKEN=abc123
export QUOTED="with spaces"
SINGLE='x=y'
EMPTY=
not a pair
`
	got, err := parseEnvFile(strings.NewReader(in))
	if err != nil {
		t.Fatal(err)
	}
	want := []envEntry{
		{"CLOUDFLARE_API_TOKEN", "abc123", "Cloudflare DNS token\nscoped to one zone"},
		{"QUOTED", "with spaces", ""},
		{"SINGLE", "x=y", ""},
		{"EMPTY", "", ""},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %#v", got)
	}
}

func TestParseInterspersed(t *testing.T) {
	fs := flag.NewFlagSet("x", flag.ContinueOnError)
	desc := fs.String("desc", "", "")
	pos := parse(fs, []string{"name", "--desc", "hello world", "other"})
	if *desc != "hello world" || !reflect.DeepEqual(pos, []string{"name", "other"}) {
		t.Fatalf("desc=%q pos=%v", *desc, pos)
	}
}

func TestParseEnvFlag(t *testing.T) {
	for in, want := range map[string]binding{
		"CF_TOKEN":              {"CF_TOKEN", "CF_TOKEN"},
		"homelab/CF_TOKEN":      {"CF_TOKEN", "homelab/CF_TOKEN"},
		"TOKEN=CF_TOKEN":        {"TOKEN", "CF_TOKEN"},
		"TOKEN=lab/CF_TOKEN":    {"TOKEN", "lab/CF_TOKEN"},
		"GH_PAT=wedding/GH_PAT": {"GH_PAT", "wedding/GH_PAT"},
	} {
		got, err := parseEnvFlag(in)
		if err != nil || got != want {
			t.Errorf("%q: got %+v, %v", in, got, err)
		}
	}
	for _, bad := range []string{"", "=X", "X=", "1X=Y", "lab/", "a-b", "lab/a-b", "A B=X",
		"a/b/C", "../X", "LAB/X", "cf_token", "API_KEY=sk-live-abc123"} {
		_, err := parseEnvFlag(bad)
		if err == nil {
			t.Errorf("%q should be rejected", bad)
		} else if bad != "" && strings.Contains(err.Error(), bad) {
			t.Errorf("error echoes the flag: %v", err)
		}
	}
}

func TestChildEnv(t *testing.T) {
	env := childEnv(
		[]string{"PATH=/bin", "KEYDROP_TOKEN=kd_fake", "TOKEN=inherited", "KEYDROP_URL=x"},
		[]binding{{"TOKEN", "CF"}, {"GH_PAT", "lab/GH_PAT"}},
		map[string]string{"CF": "fake-cf-value", "lab/GH_PAT": "fake-gh-value"},
	)
	got := map[string]string{}
	for _, kv := range env { // last wins, as in exec
		k, v, _ := strings.Cut(kv, "=")
		got[k] = v
	}
	if _, ok := got["KEYDROP_TOKEN"]; ok {
		t.Error("agent token passed to the child")
	}
	if got["TOKEN"] != "fake-cf-value" || got["GH_PAT"] != "fake-gh-value" || got["PATH"] != "/bin" {
		t.Errorf("got %v", got)
	}
}

func TestPrintable(t *testing.T) {
	for in, want := range map[string]string{
		"https://x.test":           "https://x.test",
		"a\nlab/FAKE=1":            `"a\nlab/FAKE=1"`,
		"\x1b[2Jcleared":           `"\x1b[2Jcleared"`,
		"zone id with spaces ok ü": "zone id with spaces ok ü",
	} {
		if got := printable(in); got != want {
			t.Errorf("printable(%q) = %s, want %s", in, got, want)
		}
	}
}
