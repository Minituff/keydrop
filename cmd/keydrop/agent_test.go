package main

import (
	"flag"
	"log"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/minituff/keydrop/internal/store"
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
		[]string{"PATH=/bin", "KEYDROP_TOKEN=kd_fake", "TOKEN=inherited", "KEYDROP_URL=x", "KEYDROP_TOKEN_FILE=/x/token", "KEYDROP_TLS_PIN=sha256:x"},
		[]binding{{"TOKEN", "CF"}, {"GH_PAT", "lab/GH_PAT"}},
		map[string]string{"CF": "fake-cf-value", "lab/GH_PAT": "fake-gh-value"},
	)
	got := map[string]string{}
	for _, kv := range env { // last wins, as in exec
		k, v, _ := strings.Cut(kv, "=")
		got[k] = v
	}
	for k := range got {
		if strings.HasPrefix(k, "KEYDROP_") {
			t.Errorf("%s passed to the child", k)
		}
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
		"abc\u202edcba":            `"abc\u202edcba"`,
	} {
		if got := printable(in); got != want {
			t.Errorf("printable(%q) = %s, want %s", in, got, want)
		}
	}
}

// Descriptions and other server text reach agent terminals inert.
func TestClean(t *testing.T) {
	for _, tc := range []struct {
		in        string
		multiline bool
		want      string
	}{
		{"Cloudflare token, zone ü", false, "Cloudflare token, zone ü"},
		{"\x1b[2J\x1b]0;title\x07hi", false, `\x1b[2J\x1b]0;title\x07hi`},
		{"line one\r\nfake: line", true, "line one\\x0d\nfake: line"},
		{"line one\nfake", false, `line one\x0afake`},
		{"rtl\u202eevil", false, `rtl\u202eevil`},
		{"bad \xff byte", false, `bad \xff byte`},
		{"\u009b31m", false, `\u009b31m`},
	} {
		if got := clean(tc.in, tc.multiline); got != tc.want {
			t.Errorf("clean(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

// --force replaces a symlink rather than writing through it, and the file
// is always 0600.
func TestWriteValueFile(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "elsewhere")
	os.WriteFile(target, []byte("untouched"), 0o644)
	link := filepath.Join(dir, "value")
	os.Symlink(target, link)
	if err := writeValueFile(link, "fake-value", false); err == nil {
		t.Fatal("wrote through an existing symlink without --force")
	}
	if err := writeValueFile(link, "fake-value", true); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(target); string(b) != "untouched" {
		t.Fatal("followed the symlink")
	}
	fi, _ := os.Lstat(link)
	if fi.Mode()&os.ModeSymlink != 0 || fi.Mode().Perm() != 0o600 {
		t.Fatalf("result: %v", fi.Mode())
	}
	loose := filepath.Join(dir, "loose")
	os.WriteFile(loose, []byte("old"), 0o644)
	writeValueFile(loose, "fake-value", true)
	if fi, _ := os.Stat(loose); fi.Mode().Perm() != 0o600 {
		t.Fatalf("kept mode %v", fi.Mode().Perm())
	}
}

func TestDirectAddress(t *testing.T) {
	for _, tc := range []struct {
		hosts  []string
		listen string
		want   string
	}{
		{[]string{"secrets.example.com", "10.0.0.5"}, ":8443", "https://10.0.0.5:8443"},
		{[]string{"secrets.example.com"}, ":8443", "https://secrets.example.com:8443"},
		{[]string{"fd00::5"}, "0.0.0.0:9443", "https://[fd00::5]:9443"},
		{nil, ":8443", ""},
	} {
		if got := directAddress(tc.hosts, tc.listen); got != tc.want {
			t.Errorf("directAddress(%v, %q) = %q, want %q", tc.hosts, tc.listen, got, tc.want)
		}
	}
}

// A master key file others can read is warned about.
func TestMasterKeyModeWarning(t *testing.T) {
	path := filepath.Join(t.TempDir(), "master.key")
	os.WriteFile(path, []byte(store.GenerateKey()), 0o644)
	t.Setenv("KEYDROP_MASTER_KEY_FILE", path)
	var out strings.Builder
	log.SetOutput(&out)
	defer log.SetOutput(os.Stderr)
	if _, err := masterKey(); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "mode 0644") {
		t.Fatalf("no warning: %q", out.String())
	}
	out.Reset()
	os.Chmod(path, 0o400)
	masterKey()
	if out.String() != "" {
		t.Fatalf("warned about 0400: %q", out.String())
	}
}
