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
	if envKeyToName("CLOUDFLARE_API_TOKEN") != "cloudflare-api-token" {
		t.Fatal("name conversion")
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

func TestTemplateRE(t *testing.T) {
	m := templateRE.FindAllStringSubmatch("Bearer {{cf}} and {{ lab/gh-pat }} not {{Bad}}", -1)
	if len(m) != 2 || m[0][1] != "cf" || m[1][1] != "lab/gh-pat" {
		t.Fatalf("got %v", m)
	}
}
