//go:build e2e

package e2e

import (
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// keydrop doctor with the real binary: all ok on a paired machine, the
// token line failing once the admin revokes it, and the pairing hint on
// a machine that was never paired. It never prints the token and writes
// nothing.
func TestDoctor(t *testing.T) {
	in := newInstance(t, binary)
	in.start(t, binary)
	pin := in.pin(t)
	web := setupAndLogin(t, in)
	tok := web.createToken(t, "doctor-box", "lab", false)
	g := newAgent(t, binary)
	g.login(t, in.url, pin, tok)
	stamp := filepath.Join(g.configDir(), "version-notice")
	os.Remove(stamp) // login may have left one; doctor must not

	r := g.run(t, "", "doctor")
	t.Logf("paired:\n%s", r.stdout)
	if r.code != 0 || !strings.Contains(r.stdout, "doctor-box: namespaces lab") || strings.Contains(r.stdout, "FAIL") {
		t.Fatalf("doctor on a paired machine: exit %d\n%s%s", r.code, r.stdout, r.stderr)
	}
	for _, check := range []string{"config", "server", "certificate", "token", "access", "version", "clock"} {
		if !strings.Contains(r.stdout, check) {
			t.Errorf("no %s line:\n%s", check, r.stdout)
		}
	}
	if !strings.Contains(r.stdout, "pinned ("+pin+")") {
		t.Errorf("certificate line doesn't show the pin:\n%s", r.stdout)
	}
	noLeak(t, "doctor", r.all(), tok)

	web.mustPost(t, "/tokens/doctor-box/revoke", url.Values{"confirm": {"yes"}})
	r = g.run(t, "", "doctor")
	t.Logf("revoked:\n%s", r.stdout)
	if r.code != 1 || !strings.Contains(r.stdout, "FAIL  token") || !strings.Contains(r.stdout, "keydrop pair --url "+in.url) {
		t.Fatalf("doctor after revoke: exit %d\n%s%s", r.code, r.stdout, r.stderr)
	}
	noLeak(t, "doctor", r.all(), tok)
	if _, err := os.Stat(stamp); err == nil {
		t.Error("doctor wrote the version-notice stamp")
	}
	if b, err := os.ReadFile(filepath.Join(g.configDir(), "token")); err != nil || strings.TrimSpace(string(b)) != tok {
		t.Error("doctor changed the token file")
	}

	empty := newAgent(t, binary)
	r = empty.run(t, "", "doctor")
	if r.code != 1 || !strings.Contains(r.stdout, "FAIL  config") || !strings.Contains(r.stdout, "keydrop pair --url URL") {
		t.Fatalf("doctor unpaired: exit %d\n%s%s", r.code, r.stdout, r.stderr)
	}
	if _, err := os.Stat(filepath.Join(empty.home, ".config")); !os.IsNotExist(err) {
		t.Errorf("doctor created %s", filepath.Join(empty.home, ".config"))
	}
}
