package server

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
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
	if a := h2.srv.alerts; len(a.queue) != 0 || a.heldNotice != 0 || len(a.lastNotice) != 0 {
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
		a.notice(fmt.Sprintf("notice %d", i))
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
	// take at most half the queue, and canary alerts still get in.
	a.notices = bucket{burst: 1e6, refill: time.Second, tokens: 1e6}
	for i := 0; i < 1000; i++ {
		a.notice("more")
	}
	if n := len(a.queue); n > alertQueue/2 {
		t.Fatalf("notices fill %d of %d", n, alertQueue)
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

func heldBack(a *alerter) int {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.held
}
