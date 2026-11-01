package server

import (
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"
)

var refreshMeta = regexp.MustCompile(`<meta http-equiv="refresh" content="(\d+);url=([^"]*)">`)

func TestSessionRefreshAndVersion(t *testing.T) {
	h := newHarness(t)
	h.srv.cfg.Version = "dev-test123"
	now := time.Now()
	h.srv.now = func() time.Time { return now }
	h.setup()

	_, body := h.get("/settings?msg=alerttest")
	if !strings.Contains(body, "keydrop dev-test123") {
		t.Fatal("version not on Settings")
	}
	m := refreshMeta.FindStringSubmatch(body)
	if m == nil || m[2] != "/settings" {
		t.Fatalf("refresh: %q", m)
	}
	if n, _ := strconv.Atoi(m[1]); n < int(sessionIdle/time.Second) || n > int(sessionIdle/time.Second)+5 {
		t.Fatalf("refresh after %s s", m[1])
	}

	// Near the absolute limit, the refresh comes when that runs out.
	// (stepping under the idle limit so the session stays alive).
	start := now
	for now.Sub(start) < sessionAbsolute-10*time.Minute {
		now = now.Add(min(50*time.Minute, sessionAbsolute-10*time.Minute-now.Sub(start)))
		_, body = h.get("/")
	}
	if m = refreshMeta.FindStringSubmatch(body); m == nil || m[1] != strconv.Itoa(600+5) || m[2] != "/" {
		t.Fatalf("refresh near the absolute limit: %q", m)
	}

	// A page shown after a POST reloads the start page, not the form.
	code, body := h.form("/settings/alert-webhook", url.Values{"webhook": {"not a url"}})
	if m = refreshMeta.FindStringSubmatch(body); code != http.StatusBadRequest || m == nil || m[2] != "/" {
		t.Fatalf("after POST: %d %q", code, m)
	}

	// Once it's past, the reload lands on the login page, which has no refresh.
	now = now.Add(11 * time.Minute)
	resp, err := h.web.Get(h.ts.URL + "/settings")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusSeeOther || resp.Header.Get("Location") != "/login" {
		t.Fatalf("expired: %d %s", resp.StatusCode, resp.Header.Get("Location"))
	}
	if _, body = h.get("/login"); refreshMeta.MatchString(body) || strings.Contains(body, "dev-test123") {
		t.Fatal("login page has a refresh or the version")
	}
}
