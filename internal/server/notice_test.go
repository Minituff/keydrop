package server

import (
	"bytes"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"sync"
	"testing"
	"time"
)

// inboxAlerts turns Inbox alerts on with a webhook, a configured public
// URL, and a notice budget big enough that only dedupe holds one back.
func (h *harness) inboxAlerts(publicURL string) *webhook {
	wh := h.webhook()
	h.srv.cfg.AlertInbox = true
	h.srv.cfg.PublicURL = publicURL
	h.srv.alerts.notices = bucket{burst: 100, refill: time.Minute, tokens: 100}
	return wh
}

func noticesIn(bodies []string) string { return strings.Join(bodies, "\n") }

func TestInboxAlerts(t *testing.T) {
	h := newHarness(t)
	h.setup()
	wh := h.inboxAlerts("https://secrets.example.com/")
	_, tok := h.tokenWithLifetime("bot", "lab", "30")
	_, tok2 := h.tokenWithLifetime("bot2", "lab", "30")
	h.st.PutValue("lab", "CF", []byte("fake-cf-value-1"), nil)

	// Marker strings in everything an agent or a pairing client writes.
	code, m := h.apiFrom("10.0.0.7", "POST", "/api/v1/pair", "", "", map[string]string{"host": "markhost", "user": "markuser"})
	if code != http.StatusCreated {
		t.Fatalf("pair: %d", code)
	}
	pairCode := m["code"].(string)
	h.apiFrom("10.0.0.7", "POST", "/api/v1/pair", "", "", map[string]string{}) // same address: one notice
	h.api("POST", "/api/v1/requests", tok, map[string]string{"namespace": "lab", "name": "ONE_KEY", "description": "MARK-DESC", "usage": "MARK-USAGE"})
	h.api("POST", "/api/v1/requests", tok, map[string]string{"namespace": "lab", "name": "TWO_KEY"}) // same token: one notice
	h.api("POST", "/api/v1/requests/batch", tok2, map[string]any{"namespace": "lab", "names": []string{"A_KEY", "B_KEY"}, "group": "MARK-GROUP", "description": "MARK-DESC"})
	h.api("POST", "/api/v1/token/renew", tok, nil)
	h.api("POST", "/api/v1/token/renew", tok, nil) // nothing new created
	h.api("POST", "/api/v1/secrets/lab/CF/flag", tok, map[string]string{"reason": "MARK-REASON", "link": "https://mark-link.example.com/x"})

	got := wh.all(h.srv.alerts)
	want := []string{
		"keydrop: a machine at 10.0.0.7 is asking to pair. Check its code before approving: https://secrets.example.com" + m["path"].(string),
		"keydrop: `bot` is asking for `lab/ONE_KEY`. Fill it in: https://secrets.example.com/inbox",
		"keydrop: `bot2` is asking for 2 keys in `lab`. Fill them in: https://secrets.example.com/inbox",
		"keydrop: `bot` is asking for its new token. Approve or decline: https://secrets.example.com/inbox",
		"keydrop: `bot` flagged `lab/CF`. See why: https://secrets.example.com/inbox",
	}
	if len(got) != len(want) {
		t.Fatalf("got %d notices, want %d:\n%s", len(got), len(want), noticesIn(got))
	}
	for i, w := range want {
		if !strings.Contains(got[i], `"content":"`+w+`"`) {
			t.Errorf("notice %d: got %s, want %q", i, got[i], w)
		}
	}
	all := noticesIn(got)
	for _, bad := range []string{"MARK", "markhost", "markuser", "mark-link", pairCode, strings.ReplaceAll(pairCode, "-", ""), "kd_", "fake-cf-value"} {
		if strings.Contains(all, bad) {
			t.Errorf("a notice holds %q", bad)
		}
	}
}

func TestInboxAlertsRefusedSendNothing(t *testing.T) {
	h := newHarness(t)
	h.setup()
	wh := h.inboxAlerts("https://secrets.example.com")
	tok := h.createToken("bot", "lab")
	h.st.PutValue("lab", "CF", []byte("fake-cf-value-1"), nil)
	for _, c := range []struct {
		path string
		body any
		code int
	}{
		{"/api/v1/requests", map[string]string{"namespace": "lab", "name": "CF"}, http.StatusConflict},
		{"/api/v1/requests", map[string]string{"namespace": "other", "name": "X"}, http.StatusForbidden},
		{"/api/v1/requests/batch", map[string]any{"namespace": "lab", "names": []string{"CF", "NEW"}}, http.StatusConflict},
		{"/api/v1/secrets/lab/NOPE/flag", map[string]string{"reason": "x"}, http.StatusNotFound},
		{"/api/v1/secrets/lab/CF/flag", map[string]string{"reason": "bad\u202etext"}, http.StatusBadRequest},
	} {
		if code, _, raw := h.api("POST", c.path, tok, c.body); code != c.code {
			t.Fatalf("%s: %d %s", c.path, code, raw)
		}
	}
	if got := wh.all(h.srv.alerts); len(got) != 0 {
		t.Fatalf("refused calls sent %s", noticesIn(got))
	}
	// And the refusals didn't use up the token's one notice.
	h.api("POST", "/api/v1/requests", tok, map[string]string{"namespace": "lab", "name": "NEW"})
	if got := wh.all(h.srv.alerts); len(got) != 1 {
		t.Fatalf("after a good request: %q", got)
	}
}

func TestInboxAlertsOffOrNoWebhook(t *testing.T) {
	// Off by default.
	h := newHarness(t)
	h.setup()
	wh := h.webhook()
	tok := h.createToken("bot", "lab")
	h.api("POST", "/api/v1/requests", tok, map[string]string{"namespace": "lab", "name": "ONE"})
	h.apiFrom("10.0.0.7", "POST", "/api/v1/pair", "", "", map[string]string{})
	if got := wh.all(h.srv.alerts); len(got) != 0 {
		t.Fatalf("off, but sent %q", got)
	}

	// On without a webhook: nothing queued, nothing counted.
	h2 := newHarness(t)
	h2.setup()
	h2.srv.cfg.AlertInbox = true
	tok = h2.createToken("bot", "lab")
	if code, _, _ := h2.api("POST", "/api/v1/requests", tok, map[string]string{"namespace": "lab", "name": "ONE"}); code != http.StatusCreated {
		t.Fatalf("request: %d", code)
	}
	if a := h2.srv.alerts; len(a.noteQ) != 0 || a.heldNotice != 0 || len(a.lastNotice) != 0 {
		t.Fatal("a notice went somewhere without a webhook")
	}
	if _, s := h2.get("/settings"); !strings.Contains(s, "Inbox alerts: <strong>on</strong>, but they need a webhook") {
		t.Fatal("Settings doesn't say Inbox alerts need a webhook")
	}
	if _, s := h.get("/settings"); !strings.Contains(s, "Inbox alerts: <strong>off</strong>") || !strings.Contains(s, "KEYDROP_ALERT_INBOX") {
		t.Fatal("Settings doesn't say Inbox alerts are off")
	}
}

// Without a configured public URL there's no link, not a guessed one.
func TestInboxAlertsNoLink(t *testing.T) {
	for _, guess := range []bool{false, true} {
		h := newHarness(t)
		h.setup()
		url := ""
		if guess {
			url = "https://localhost:8443"
		}
		wh := h.inboxAlerts(url)
		h.srv.cfg.PublicURLGuess = guess
		tok := h.createToken("bot", "lab")
		h.api("POST", "/api/v1/requests", tok, map[string]string{"namespace": "lab", "name": "ONE"})
		h.apiFrom("10.0.0.7", "POST", "/api/v1/pair", "", "", map[string]string{})
		all := noticesIn(wh.all(h.srv.alerts))
		if !strings.Contains(all, "Fill it in. Open keydrop's Inbox.") || !strings.Contains(all, "before approving. Open keydrop's Agents page.") || strings.Contains(all, "http") {
			t.Fatalf("guess %v: %s", guess, all)
		}
	}
}

// A flag on a canary answers exactly like one on an ordinary secret. It
// sends the canary alert and no notice; the ordinary one sends a notice.
func TestInboxAlertsCanaryFlag(t *testing.T) {
	h := newHarness(t)
	h.setup()
	wh := h.inboxAlerts("https://secrets.example.com")
	tok := h.createToken("bot", "lab")
	h.st.PutValue("lab", "REAL_KEY", []byte("fake-real-value-1"), nil)
	h.st.PutValue("lab", "BAIT_KEY", []byte("fake-bait-value-1"), nil)
	if err := h.st.SetCanary("lab", "BAIT_KEY", true); err != nil {
		t.Fatal(err)
	}
	body := map[string]string{"reason": "returns 401"}
	code1, _, real := h.api("POST", "/api/v1/secrets/lab/REAL_KEY/flag", tok, body)
	code2, _, bait := h.api("POST", "/api/v1/secrets/lab/BAIT_KEY/flag", tok, body)
	if code1 != code2 || strings.ReplaceAll(string(bait), "BAIT", "REAL") != string(real) {
		t.Fatalf("real %d %s, canary %d %s", code1, real, code2, bait)
	}
	all := noticesIn(wh.all(h.srv.alerts))
	if !strings.Contains(all, "flagged `lab/REAL_KEY`") || !strings.Contains(all, "canary `lab/BAIT_KEY` was flagged") || strings.Contains(all, "flagged `lab/BAIT_KEY`") {
		t.Fatalf("webhook got %s", all)
	}
}

// A flood of notices (pairing needs no credential) leaves the security
// alerts' budget and half the queue alone.
func TestInboxNoticeFlood(t *testing.T) {
	var mu sync.Mutex
	var got []string
	release := make(chan struct{})
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-release
		buf, _ := io.ReadAll(r.Body)
		mu.Lock()
		got = append(got, string(buf))
		mu.Unlock()
	}))
	t.Cleanup(ts.Close)
	t.Cleanup(func() {
		select {
		case <-release:
		default:
			close(release)
		}
	})
	now := time.Now()
	a := newAlerter(ts.URL)
	a.now = func() time.Time { return now }

	for i := 0; i < 1000; i++ {
		a.notice(agentNotice, fmt.Sprintf("notice %d", i))
	}
	a.mu.Lock()
	if a.budget.tokens != alertBurst || a.heldNotice != 1000-noticeBurst {
		t.Fatalf("budget %v, held notices %d", a.budget.tokens, a.heldNotice)
	}
	a.mu.Unlock()
	a.send("keydrop: canary alert")
	if heldBack(a) != 0 {
		t.Fatal("the canary alert was held back after 1,000 notices")
	}

	// Even with an unlimited notice budget and a stuck webhook, notices
	// wait in their own queue, half the size, and canary alerts still
	// get in.
	a.notices = bucket{burst: 1e6, refill: time.Second, tokens: 1e6}
	for i := 0; i < 1000; i++ {
		a.notice(agentNotice, "more")
	}
	a.mu.Lock()
	n := len(a.noteQ)
	a.mu.Unlock()
	if n > alertQueue/2 {
		t.Fatalf("notices fill %d of %d", n, alertQueue/2)
	}
	for i := 0; i < alertBurst-1; i++ {
		a.send(fmt.Sprintf("keydrop: canary alert %d", i))
	}
	if n := heldBack(a); n != 0 {
		t.Fatalf("%d canary alerts held back by notices", n)
	}

	// What was held back comes out as one summary, on the notices' budget.
	close(release)
	a.wg.Wait()
	a.notices = bucket{burst: noticeBurst, refill: noticeRefill, tokens: 1}
	held := a.heldNotice
	a.flushHeld()
	a.wg.Wait()
	mu.Lock()
	defer mu.Unlock()
	all := strings.Join(got, "\n")
	if !strings.Contains(all, "canary alert\"") || !strings.Contains(all, "canary alert 3") {
		t.Fatal("canary alerts not delivered")
	}
	if !strings.Contains(all, fmt.Sprintf("keydrop: %d more things are waiting for you", held)) || a.heldNotice != 0 || a.budget.tokens != 0 {
		t.Fatalf("summary: held %d, budget %v", a.heldNotice, a.budget.tokens)
	}
}

// Pairing needs no credential, so its notices have their own budget: a
// flood of pairing requests from many addresses doesn't stop an agent's
// request, flag or renewal notice going out at once (the audit's
// TestPoCNoticeBudgetStarved, inverted). The default budgets throughout.
func TestPairingFloodLeavesAgentNotices(t *testing.T) {
	h := newHarness(t)
	h.setup()
	wh := h.webhook()
	h.srv.cfg.AlertInbox = true
	_, tok := h.tokenWithLifetime("bot", "lab", "30")
	for i := range 50 {
		h.apiFrom(fmt.Sprintf("203.0.113.%d", i+1), "POST", "/api/v1/pair", "", "", map[string]string{})
	}
	h.api("POST", "/api/v1/requests", tok, map[string]string{"namespace": "lab", "name": "REAL_KEY"})
	h.api("POST", "/api/v1/secrets/lab/REAL_KEY/flag", tok, map[string]string{"reason": "x"})
	h.api("POST", "/api/v1/token/renew", tok, nil)
	all := noticesIn(wh.all(h.srv.alerts))
	for _, want := range []string{"`bot` is asking for `lab/REAL_KEY`", "`bot` flagged `lab/REAL_KEY`", "`bot` is asking for its new token"} {
		if !strings.Contains(all, want) {
			t.Fatalf("%q not delivered after a pairing flood:\n%s", want, all)
		}
	}
	a := h.srv.alerts
	a.mu.Lock()
	heldPair, heldNotice := a.heldPair, a.heldNotice
	a.pairs.tokens = 1
	a.mu.Unlock()
	if n := strings.Count(all, "asking to pair"); n != pairBurst || heldPair != 50-pairBurst || heldNotice != 0 {
		t.Fatalf("%d pairing notices sent, %d held; %d agents' notices held", n, heldPair, heldNotice)
	}
	// The pairing summary comes out on the pairing budget.
	a.flushHeld()
	if all := noticesIn(wh.all(a)); !strings.Contains(all, fmt.Sprintf("keydrop: %d more machines asked to pair", 50-pairBurst)) || heldPairs(a) != 0 {
		t.Fatalf("no pairing summary:\n%s", all)
	}
}

// Pairing notices are deduplicated in a map of their own. Filling it (more
// than maxAlertKeys address groups in alertEvery) neither blocks agents'
// notices nor drops pairing notices silently: they're counted for the
// summary (the audit's TestPoCNoticeKeyCapSilentDrop, inverted).
func TestPairingMapFullCounted(t *testing.T) {
	h := newHarness(t)
	h.setup()
	wh := h.inboxAlerts("https://secrets.example.com")
	tok := h.createToken("bot", "lab")
	for i := 0; i <= maxAlertKeys; i++ {
		h.apiFrom(fmt.Sprintf("2001:db8:%x:%x::1", i>>16, i&0xffff), "POST", "/api/v1/pair", "", "", map[string]string{})
	}
	a := h.srv.alerts
	a.wg.Wait()
	a.mu.Lock()
	a.pairs = bucket{burst: 100, refill: time.Minute, tokens: 100} // the budget isn't the cause
	held, keys, agentKeys := a.heldPair, len(a.lastPair), len(a.lastNotice)
	a.mu.Unlock()
	if keys != maxAlertKeys+1 || agentKeys != 0 {
		t.Fatalf("pairing map %d, agents' map %d", keys, agentKeys)
	}
	h.apiFrom("2001:db8:ffff:ffff::1", "POST", "/api/v1/pair", "", "", map[string]string{})
	a.mu.Lock()
	heldNow, keysNow := a.heldPair, len(a.lastPair)
	a.mu.Unlock()
	if heldNow != held+1 || keysNow != keys {
		t.Fatalf("a pairing notice refused by the full map: held %d -> %d", held, heldNow)
	}
	if code, _, raw := h.api("POST", "/api/v1/requests", tok, map[string]string{"namespace": "lab", "name": "REAL_KEY"}); code != http.StatusCreated {
		t.Fatal(code, raw)
	}
	if all := noticesIn(wh.all(a)); !strings.Contains(all, "`bot` is asking for `lab/REAL_KEY`") {
		t.Fatal("an agent's notice blocked by the full pairing map")
	}
}

// Pairing notices fill at most half the notice queue, so with a stuck
// webhook and no pairing budget limit, agents' notices still get in.
func TestPairingNoticesQueueShare(t *testing.T) {
	release := make(chan struct{})
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { <-release }))
	t.Cleanup(ts.Close)
	t.Cleanup(func() { close(release) })
	a := newAlerter(ts.URL)
	a.pairs = bucket{burst: 1e6, refill: time.Second, tokens: 1e6}
	for range 1000 {
		a.notice(pairNotice, "pair")
	}
	a.mu.Lock()
	n := len(a.noteQ)
	a.mu.Unlock()
	if n > alertQueue/4 {
		t.Fatalf("pairing notices fill %d of %d", n, alertQueue)
	}
	for i := range noticeBurst {
		a.notice(agentNotice, fmt.Sprintf("agent %d", i))
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.heldNotice != 0 {
		t.Fatalf("%d agents' notices held back by pairing notices", a.heldNotice)
	}
}

func heldPairs(a *alerter) int {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.heldPair
}

func heldBack(a *alerter) int {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.held
}

// The Settings choice wins over KEYDROP_ALERT_INBOX once made, on or off;
// "default" goes back to the variable. The form is an audit-logged admin
// form.
func TestInboxAlertsSetting(t *testing.T) {
	for _, env := range []bool{false, true} {
		h := newHarness(t)
		h.setup()
		wh := h.inboxAlerts("")
		h.srv.cfg.AlertInbox = env
		n := 0
		// sends reports whether a request by a new token sends a notice.
		sends := func() bool {
			t.Helper()
			n++
			name := fmt.Sprintf("bot%d", n)
			tok := h.createToken(name, "lab")
			if code, _, _ := h.api("POST", "/api/v1/requests", tok, map[string]string{"namespace": "lab", "name": "KEY_" + fmt.Sprint(n)}); code != http.StatusCreated {
				t.Fatalf("request: %d", code)
			}
			return strings.Contains(noticesIn(wh.all(h.srv.alerts)), "`"+name+"` is asking")
		}
		pressed := func(want string) {
			t.Helper()
			_, page := h.get("/settings")
			if !strings.Contains(page, `value="`+want+`" class="on small" aria-pressed="true"`) {
				t.Fatalf("env %v: %q isn't the pressed choice", env, want)
			}
			if !strings.Contains(page, fmt.Sprintf("Default (%s)", onOff(env))) {
				t.Fatalf("env %v: the default isn't shown", env)
			}
		}
		pressed("default")
		if got := sends(); got != env {
			t.Fatalf("env %v, no choice: notice %v", env, got)
		}
		for _, c := range []string{"on", "off"} {
			if code, _ := h.form("/settings/alert-inbox", url.Values{"inbox": {c}}); code != http.StatusSeeOther {
				t.Fatalf("env %v, %s: %d", env, c, code)
			}
			pressed(c)
			if got := sends(); got != (c == "on") {
				t.Fatalf("env %v, %s: notice %v", env, c, got)
			}
			if !h.auditHas("settings.alertinbox", c) {
				t.Fatalf("env %v, %s: not in the audit log", env, c)
			}
		}
		if code, _ := h.form("/settings/alert-inbox", url.Values{"inbox": {"default"}}); code != http.StatusSeeOther {
			t.Fatalf("env %v, default: %d", env, code)
		}
		pressed("default")
		if got := sends(); got != env {
			t.Fatalf("env %v, back to the default: notice %v", env, got)
		}
		if !h.auditHas("settings.alertinbox", "the default, from KEYDROP_ALERT_INBOX") {
			t.Fatalf("env %v, default: not in the audit log", env)
		}

		// Refused: an unknown choice, no CSRF token, no session. Nothing
		// changes.
		want := !env
		h.st.SetInboxAlerts(&want)
		if code, _ := h.form("/settings/alert-inbox", url.Values{"inbox": {"maybe"}}); code != http.StatusBadRequest {
			t.Fatalf("unknown choice: %d", code)
		}
		if resp := h.post("/settings/alert-inbox", url.Values{"inbox": {"default"}}); resp.StatusCode != http.StatusForbidden {
			t.Fatalf("without csrf: %d", resp.StatusCode)
		}
		anon := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
		resp, err := anon.PostForm(h.ts.URL+"/settings/alert-inbox", url.Values{"inbox": {"default"}})
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusSeeOther || resp.Header.Get("Location") != "/login" {
			t.Fatalf("logged out: %d %s", resp.StatusCode, resp.Header.Get("Location"))
		}
		if on, chosen := h.st.InboxAlerts(); on != want || !chosen {
			t.Fatalf("env %v: a refused form changed the setting: %v %v", env, on, chosen)
		}
	}
}

// The startup log says what's in effect and where it came from.
func TestInboxAlertsStartupLog(t *testing.T) {
	var buf bytes.Buffer
	log.SetOutput(&buf)
	defer log.SetOutput(os.Stderr)
	h := newHarness(t)
	on, off := true, false
	for _, c := range []struct {
		env    bool
		choice *bool
		want   string
	}{
		{false, nil, ""},
		{true, nil, "Inbox alerts: on (KEYDROP_ALERT_INBOX)"},
		{false, &on, "Inbox alerts: on (set in Settings)"},
		{true, &off, "Inbox alerts: off (turned off in Settings, which wins over KEYDROP_ALERT_INBOX)"},
		{false, &off, ""},
	} {
		if err := h.st.SetInboxAlerts(c.choice); err != nil {
			t.Fatal(err)
		}
		buf.Reset()
		New(Config{AlertInbox: c.env, AlertWebhook: "https://hooks.example.com/fake-hook"}, h.st, h.srv.audit)
		got := buf.String()
		if c.want == "" && strings.Contains(got, "Inbox alerts") || !strings.Contains(got, c.want) {
			t.Fatalf("env %v, choice %v: %q", c.env, c.choice, got)
		}
	}
}

// The sender takes security alerts ahead of notices already queued: a
// canary alert waits only for the message being posted when it arrives.
func TestSecurityAlertsSentFirst(t *testing.T) {
	var mu sync.Mutex
	var got []string
	first := make(chan struct{})
	release := make(chan struct{})
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		buf, _ := io.ReadAll(r.Body)
		mu.Lock()
		got = append(got, string(buf))
		n := len(got)
		mu.Unlock()
		if n == 1 {
			close(first)
			<-release // the webhook is slow with the first notice
		}
	}))
	t.Cleanup(ts.Close)
	a := newAlerter(ts.URL)
	a.notices = bucket{burst: 100, refill: time.Second, tokens: 100}
	a.notice(agentNotice, "notice 0")
	<-first // being posted
	for i := 1; i <= 5; i++ {
		a.notice(agentNotice, fmt.Sprintf("notice %d", i))
	}
	a.send("canary alert")
	close(release)
	a.wg.Wait()
	mu.Lock()
	defer mu.Unlock()
	if len(got) != 7 || !strings.Contains(got[0], "notice 0") || !strings.Contains(got[1], "canary alert") {
		t.Fatalf("order: %v", got)
	}
}
