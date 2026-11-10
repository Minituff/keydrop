package server

import (
	"bytes"
	"log"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"
)

// KEYDROP_RESET_ADMIN left set reopens setup on every restart, so the log
// says so loudly when an admin exists, and again once setup is done. It
// never holds the password or the authenticator key.
func TestResetAdminWarns(t *testing.T) {
	var buf bytes.Buffer
	log.SetOutput(&buf)
	defer log.SetOutput(os.Stderr)

	h := newHarness(t)
	if strings.Contains(buf.String(), "KEYDROP_RESET_ADMIN") {
		t.Fatalf("first-run setup warned about KEYDROP_RESET_ADMIN:\n%s", buf.String())
	}
	h.setup()

	// Restart with the variable set.
	buf.Reset()
	srv := New(Config{ResetAdmin: true}, h.st, h.srv.audit)
	ts := httptest.NewServer(srv)
	defer ts.Close()
	out := buf.String()
	if !strings.Contains(out, "WARNING") || !strings.Contains(out, "KEYDROP_RESET_ADMIN is set") || !srv.setupOpen() {
		t.Fatalf("no warning on a reset start:\n%s", out)
	}
	if w, c := strings.Index(out, "WARNING"), strings.Index(out, "setup code"); w > c {
		t.Fatalf("the warning comes after the code:\n%s", out)
	}

	buf.Reset()
	jar, _ := cookiejar.New(nil)
	web := &http.Client{Jar: jar, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	const pw = "a different long password"
	resp, err := web.PostForm(ts.URL+"/setup", url.Values{
		"code": {srv.setupCode}, "password": {pw}, "password2": {pw},
		"mfa": {"totp"}, "totp": {totpNow(srv.setupSeed, time.Now())},
	})
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("reset setup: %d", resp.StatusCode)
	}
	out = buf.String()
	if !strings.Contains(out, "remove KEYDROP_RESET_ADMIN and restart") {
		t.Fatalf("no reminder after setup:\n%s", out)
	}
	if strings.Contains(out, pw) {
		t.Fatal("the password was logged")
	}
}
