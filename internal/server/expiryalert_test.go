package server

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/minituff/keydrop/internal/store"
)

// expiryAlerts turns expiry alerts on for days, with a webhook, a public
// URL and a clock the test moves, and a notice budget only the test exhausts.
func (h *harness) expiryAlerts(days int, publicURL string) (*webhook, *clock) {
	h.t.Helper()
	wh := h.webhook()
	h.srv.cfg.PublicURL = publicURL
	h.srv.alerts.notices = bucket{burst: 100, refill: time.Minute, tokens: 100}
	if err := h.st.SetExpiryAlertDays(days); err != nil {
		h.t.Fatal(err)
	}
	return wh, h.clock()
}

// expiringKey stores ns/name with a value and an expiry at, and text an agent or
// the admin might write that must never reach the webhook.
func (h *harness) expiringKey(ns, name string, at time.Time, variable bool) {
	h.t.Helper()
	m := &store.Meta{Description: "MARK-DESC", Usage: "MARK-USAGE", Expires: &at, Variable: variable}
	if err := h.st.PutValue(ns, name, []byte("fake-MARK-value-"+name), m); err != nil {
		h.t.Fatal(err)
	}
}

// check runs one expiry check and returns what it sent.
func (wh *webhook) check(h *harness) []string {
	n := len(wh.all(h.srv.alerts))
	h.srv.checkExpiry()
	return wh.all(h.srv.alerts)[n:]
}

const day = 24 * time.Hour

func TestExpiryAlertsOffByDefault(t *testing.T) {
	h := newHarness(t)
	h.setup()
	wh, c := h.expiryAlerts(0, "https://secrets.example.com")
	h.expiringKey("lab", "CF_TOKEN", c.now().Add(2*day), false)
	h.expiringKey("lab", "OLD", c.now().Add(-2*day), false)
	if got := wh.check(h); len(got) != 0 {
		t.Fatalf("off, but sent %q", got)
	}
}

func TestExpiryAlerts(t *testing.T) {
	h := newHarness(t)
	h.setup()
	wh, c := h.expiryAlerts(14, "https://secrets.example.com/")
	now := c.now()
	h.expiringKey("lab", "CF_TOKEN", now.Add(3*day+time.Hour), false)
	h.expiringKey("lab", "GH_PAT", now.Add(20*day), false) // outside the window
	h.expiringKey("media", "PLEX", now.Add(-2*day-time.Hour), false)
	h.expiringKey("lab", "API_URL", now.Add(5*day+time.Hour), true) // variables too
	h.expiringKey("lab", "NO_DATE", now, false)
	h.st.UpdateMeta("lab", "NO_DATE", store.Meta{})
	// A canary's date is there to look real: never announced.
	h.expiringKey("lab", "BAIT_KEY", now.Add(day), false)
	if err := h.st.SetCanary("lab", "BAIT_KEY", true); err != nil {
		t.Fatal(err)
	}
	// A pending request has no value to expire.
	if err := h.st.Request("lab", "WANTED", "MARK-DESC", "MARK-USAGE", "bot"); err != nil {
		t.Fatal(err)
	}
	soon := now.Add(day)
	h.st.UpdateMeta("lab", "WANTED", store.Meta{Expires: &soon})

	got := wh.check(h)
	want := "keydrop: 2 keys expire within 14 days and 1 key has expired: `media/PLEX` (expired 2 days ago), `lab/CF_TOKEN` (in 3 days), `lab/API_URL` (in 5 days). Renew them: https://secrets.example.com/"
	if len(got) != 1 || !strings.Contains(got[0], `"content":"`+want+`"`) {
		t.Fatalf("got %q, want %q", got, want)
	}
	for _, bad := range []string{"MARK", "BAIT", "WANTED", "GH_PAT", "NO_DATE"} {
		if strings.Contains(got[0], bad) {
			t.Errorf("the digest holds %q", bad)
		}
	}
	if got := wh.check(h); len(got) != 0 {
		t.Fatalf("the next check sent %q", got)
	}

	// CF_TOKEN passes its date: one more, once.
	c.add(3*day + 2*time.Hour)
	want = "keydrop: 1 key has expired: `lab/CF_TOKEN` (expired today). Renew it: https://secrets.example.com/"
	if got := wh.check(h); len(got) != 1 || !strings.Contains(got[0], want) {
		t.Fatalf("got %q, want %q", got, want)
	}
	if got := wh.check(h); len(got) != 0 {
		t.Fatalf("the next check sent %q", got)
	}

	// A new date re-arms it; GH_PAT (now 16 days off) comes into a wider
	// window once the setting changes.
	later := c.now().Add(9*day + time.Hour)
	h.st.UpdateMeta("lab", "CF_TOKEN", store.Meta{Expires: &later})
	want = "keydrop: 1 key expires within 14 days: `lab/CF_TOKEN` (in 9 days). Renew it"
	if got := wh.check(h); len(got) != 1 || !strings.Contains(got[0], want) {
		t.Fatalf("got %q, want %q", got, want)
	}
	h.st.SetExpiryAlertDays(30)
	want = "keydrop: 1 key expires within 30 days: `lab/GH_PAT` (in 16 days)."
	if got := wh.check(h); len(got) != 1 || !strings.Contains(got[0], want) {
		t.Fatalf("got %q, want %q", got, want)
	}

	// Off forgets what was announced; on again announces what's in the
	// window.
	h.st.SetExpiryAlertDays(0)
	if got := wh.check(h); len(got) != 0 {
		t.Fatalf("off, but sent %q", got)
	}
	h.st.SetExpiryAlertDays(7)
	if got := wh.check(h); len(got) != 1 || !strings.Contains(got[0], "keydrop: 1 key expires within 7 days and 1 key has expired: `media/PLEX` (expired 5 days ago), `lab/API_URL` (in 1 day). Renew them") {
		t.Fatalf("on again: %q", got)
	}
}

// Many keys at once: one digest, names past the cap counted.
func TestExpiryAlertsDigestCap(t *testing.T) {
	h := newHarness(t)
	h.setup()
	wh, c := h.expiryAlerts(7, "")
	for i := 0; i < maxExpiryNames+4; i++ {
		h.expiringKey("lab", fmt.Sprintf("KEY_%02d", i), c.now().Add(time.Duration(i+1)*time.Hour), false)
	}
	got := wh.check(h)
	if len(got) != 1 {
		t.Fatalf("%d messages", len(got))
	}
	if !strings.Contains(got[0], "keydrop: 12 keys expire within 7 days: `lab/KEY_00` (in less than a day), ") ||
		!strings.Contains(got[0], "`lab/KEY_07` (in less than a day) and 4 more. Renew them. Open keydrop's Secrets page.") ||
		strings.Contains(got[0], "KEY_08") {
		t.Fatalf("got %s", got[0])
	}
}

// Without a webhook nothing is sent or marked; once one is added the keys
// are announced.
func TestExpiryAlertsNoWebhook(t *testing.T) {
	h := newHarness(t)
	h.setup()
	c := h.clock()
	h.st.SetExpiryAlertDays(14)
	h.expiringKey("lab", "CF_TOKEN", c.now().Add(3*day), false)
	h.srv.checkExpiry()
	if a := h.srv.alerts; len(a.noteQ) != 0 || a.heldNotice != 0 || h.srv.expiryMarks != nil {
		t.Fatal("something was sent or marked without a webhook")
	}
	if _, s := h.get("/settings"); !strings.Contains(s, "Warn me before a key expires: <strong>14 days ahead</strong>, but it needs a webhook") {
		t.Fatal("Settings doesn't say expiry alerts need a webhook")
	}
	wh := h.webhook()
	if got := wh.check(h); len(got) != 1 || !strings.Contains(got[0], "`lab/CF_TOKEN`") {
		t.Fatalf("after adding a webhook: %q", got)
	}
}

// Link only with a configured public URL, not a guessed one.
func TestExpiryAlertsLink(t *testing.T) {
	for _, guess := range []bool{false, true} {
		h := newHarness(t)
		h.setup()
		wh, c := h.expiryAlerts(7, "https://localhost:8443")
		h.srv.cfg.PublicURLGuess = guess
		h.expiringKey("lab", "CF_TOKEN", c.now().Add(3*day), false)
		got := wh.check(h)
		link := strings.Contains(got[0], ": https://localhost:8443/\"")
		if len(got) != 1 || link == guess || guess && !strings.Contains(got[0], "Renew it. Open keydrop's Secrets page.") {
			t.Fatalf("guess %v: %q", guess, got)
		}
	}
}

// The digest goes on the notices' budget. With that spent it isn't sent,
// counted or marked, and goes out at the next check that has room; the
// security budget is untouched and a canary alert goes out at once.
func TestExpiryAlertsBudget(t *testing.T) {
	h := newHarness(t)
	h.setup()
	wh, c := h.expiryAlerts(30, "")
	for i := 0; i < 200; i++ {
		h.expiringKey("lab", fmt.Sprintf("KEY_%03d", i), c.now().Add(time.Duration(i+1)*time.Hour), false)
	}
	a := h.srv.alerts
	a.notices = bucket{burst: noticeBurst, refill: time.Hour, tokens: 0, filled: time.Now()}
	got := wh.check(h)
	a.mu.Lock()
	held := a.heldNotice
	a.mu.Unlock()
	if len(got) != 0 || h.srv.expiryMarks != nil || held != 0 {
		t.Fatalf("over budget: sent %q, held %d", got, held)
	}
	a.send("keydrop: canary alert")
	if got := wh.all(a); len(got) != 1 || !strings.Contains(got[0], "canary alert") || heldBack(a) != 0 {
		t.Fatalf("the canary alert: %q", got)
	}
	a.mu.Lock()
	a.notices.tokens = 1
	a.mu.Unlock()
	got = wh.check(h)
	a.mu.Lock()
	security := a.budget.tokens
	a.mu.Unlock()
	if len(got) != 1 || !strings.Contains(got[0], "200 keys expire within 30 days: ") || security != alertBurst-1 {
		t.Fatalf("with room: %q, security budget %v", got, security)
	}
	if got := wh.check(h); len(got) != 0 {
		t.Fatalf("again: %q", got)
	}
}

// The form is a CSRF-checked, audit-logged admin form, and it asks the
// background loop for a check, which stops with its context.
func TestExpiryAlertsSettingAndLoop(t *testing.T) {
	h := newHarness(t)
	h.setup()
	wh, c := h.expiryAlerts(0, "")
	h.expiringKey("lab", "CF_TOKEN", c.now().Add(3*day), false)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { h.srv.runExpiryChecks(ctx, time.Hour, time.Hour); close(done) }()
	t.Cleanup(func() { cancel(); <-done })

	for _, bad := range []string{"", "5", "x", "-7", "365"} {
		if code, _ := h.form("/settings/alert-expiry", url.Values{"days": {bad}}); code != http.StatusBadRequest {
			t.Fatalf("%q: %d", bad, code)
		}
	}
	if resp := h.post("/settings/alert-expiry", url.Values{"days": {"7"}}); resp.StatusCode != http.StatusForbidden {
		t.Fatalf("without csrf: %d", resp.StatusCode)
	}
	anon := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	resp, err := anon.PostForm(h.ts.URL+"/settings/alert-expiry", url.Values{"days": {"7"}})
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusSeeOther || resp.Header.Get("Location") != "/login" || h.st.ExpiryAlertDays() != 0 {
		t.Fatalf("logged out: %d %s", resp.StatusCode, resp.Header.Get("Location"))
	}

	code, page := h.form("/settings/alert-expiry", url.Values{"days": {"7"}})
	if code != http.StatusSeeOther || h.st.ExpiryAlertDays() != 7 || !h.auditHas("settings.alertexpiry", "7 days") ||
		!strings.Contains(page, `value="7" class="on small" aria-pressed="true"`) {
		t.Fatalf("7 days: %d", code)
	}
	deadline := time.Now().Add(5 * time.Second)
	for len(wh.all(h.srv.alerts)) == 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if got := wh.all(h.srv.alerts); len(got) != 1 || !strings.Contains(got[0], "`lab/CF_TOKEN` (in 3 days)") {
		t.Fatalf("after turning it on: %q", got)
	}
	code, page = h.form("/settings/alert-expiry", url.Values{"days": {"0"}})
	if code != http.StatusSeeOther || h.st.ExpiryAlertDays() != 0 || !h.auditHas("settings.alertexpiry", "off") ||
		!strings.Contains(page, `value="0" class="on small" aria-pressed="true"`) {
		t.Fatalf("off: %d", code)
	}
	cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("the background loop didn't stop")
	}
}
