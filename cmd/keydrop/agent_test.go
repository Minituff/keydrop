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
	for _, bad := range []string{"", "=X", "X=", "1X=Y", "lab/", "a-b", "lab/a-b", "A B=X"} {
		if _, err := parseEnvFlag(bad); err == nil {
			t.Errorf("%q should be rejected", bad)
		}
	}
}
