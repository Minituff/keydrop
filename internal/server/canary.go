package server

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/minituff/keydrop/internal/store"
)

// Canaries: decoy secrets whose every read by an agent is an alarm. To the
// agent a canary is an ordinary secret (same responses, same errors, same
// work per read); only the admin's pages show it.

const (
	// alertTimeout bounds one webhook POST. Sent in the background, so the
	// request that caused it never waits.
	alertTimeout = 5 * time.Second
	// alertEvery is the least time between two alerts for the same canary
	// and token. Every touch is still in the audit log and the Inbox.
	alertEvery = 10 * time.Minute
	// alertBurst and alertRefill are the global budget: at most alertBurst
	// alerts at once, then one per alertRefill. What's over it is counted
	// and sent as one summary when the budget allows.
	alertBurst  = 5
	alertRefill = time.Minute
	// alertQueue is how many alerts may wait to be sent.
	alertQueue = 32
	// alertRetries and maxRetryAfter bound how long a 429 is waited out.
	alertRetries  = 2
	maxRetryAfter = 30 * time.Second
)

// alerter POSTs alerts to the configured webhook, one at a time from one
// goroutine. The URL is a credential (anyone with it can post to the
// channel): it's never logged, shown, put in an error or written to the
// audit log.
type alerter struct {
	client *http.Client
	now    func() time.Time
	queue  chan []byte
	once   sync.Once
	wg     sync.WaitGroup // alerts queued and not yet sent, for tests

	mu     sync.Mutex
	url    string               // set with setURL; read with webhook
	dest   alertDest            // where url posts, for Settings
	last   map[string]time.Time // canary ref + token -> last alert
	tokens float64              // the global budget
	filled time.Time
	held   int // alerts over the budget, for the next summary
	sleep  func(time.Duration)
}

func newAlerter(webhook string) *alerter {
	return &alerter{
		url: webhook,
		client: &http.Client{
			Timeout: alertTimeout,
			// A redirect could take the alert (and the URL's path) somewhere
			// else; a webhook answers directly.
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		},
		now:    time.Now,
		queue:  make(chan []byte, alertQueue),
		last:   map[string]time.Time{},
		tokens: alertBurst,
		sleep:  time.Sleep,
	}
}

// CheckAlertWebhook validates KEYDROP_ALERT_WEBHOOK without repeating it in
// the error.
func CheckAlertWebhook(raw string) error {
	if raw == "" {
		return nil
	}
	u, err := url.Parse(raw)
	if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" {
		return errors.New("KEYDROP_ALERT_WEBHOOK must be an http:// or https:// URL (its value isn't shown here)")
	}
	return nil
}

func (a *alerter) configured() bool { return a.webhook() != "" }

func (a *alerter) webhook() string {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.url
}

// setURL changes where alerts go, including those already queued. The
// destination is looked up again (describe).
func (a *alerter) setURL(u string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.url, a.dest = u, alertDest{}
}

// allow reports whether an alert for key may go out now (one per key per
// alertEvery), and if so counts it.
func (a *alerter) allow(key string, now time.Time) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	if last, ok := a.last[key]; ok && now.Sub(last) < alertEvery {
		return false
	}
	if len(a.last) > 10000 {
		for k, t := range a.last {
			if now.Sub(t) >= alertEvery {
				delete(a.last, k)
			}
		}
	}
	a.last[key] = now
	return true
}

// take spends one from the global budget, if there is one. Needs a.mu.
func (a *alerter) take(now time.Time) bool {
	if !a.filled.IsZero() {
		a.tokens = min(alertBurst, a.tokens+float64(now.Sub(a.filled))/float64(alertRefill))
	}
	a.filled = now
	if a.tokens < 1 {
		return false
	}
	a.tokens--
	return true
}

// send queues content for the webhook. Over the global budget, or with the
// queue full, it's counted instead, and a summary goes out later.
func (a *alerter) send(content string) {
	if !a.configured() {
		return
	}
	a.once.Do(func() { go a.run() })
	a.mu.Lock()
	defer a.mu.Unlock()
	if !a.take(a.now()) || !a.enqueue(content) {
		a.held++
	}
}

// enqueue queues one message without blocking. Needs a.mu.
func (a *alerter) enqueue(content string) bool {
	// No mentions: the content names tokens and secrets, which mustn't
	// ping anyone.
	body, _ := json.Marshal(map[string]any{"content": content, "allowed_mentions": map[string]any{"parse": []string{}}})
	a.wg.Add(1)
	select {
	case a.queue <- body:
		return true
	default:
		a.wg.Done()
		return false
	}
}

// run sends the queue, and every alertRefill a summary of what was held
// back, when the budget allows one.
func (a *alerter) run() {
	tick := time.NewTicker(alertRefill)
	defer tick.Stop()
	for {
		select {
		case body := <-a.queue:
			if err := a.post(body); err != nil {
				log.Printf("alert webhook: %v", err)
			}
			a.wg.Done()
		case <-tick.C:
			a.flushHeld()
		}
	}
}

// flushHeld sends one summary of the alerts held back, if the budget has
// room.
func (a *alerter) flushHeld() {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.held == 0 || !a.take(a.now()) {
		return
	}
	if a.enqueue(fmt.Sprintf("keydrop: %d more alerts were held back by the rate limit; see keydrop's Inbox and audit log.", a.held)) {
		a.held = 0
	}
}

func (a *alerter) post(body []byte) error {
	for try := 0; ; try++ {
		wait, err := a.postOnce(body)
		if wait == 0 || try >= alertRetries {
			return err
		}
		a.sleep(wait)
	}
}

// postOnce sends body once. On a 429 it returns how long to wait before
// trying again (the Retry-After, at most maxRetryAfter).
func (a *alerter) postOnce(body []byte) (time.Duration, error) {
	ctx, cancel := context.WithTimeout(context.Background(), alertTimeout)
	defer cancel()
	u := a.webhook()
	if u == "" {
		return 0, errors.New("no webhook is configured")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u, bytes.NewReader(body))
	if err != nil {
		return 0, errors.New("couldn't build the request")
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := a.client.Do(req)
	if err != nil {
		if errors.Is(err, context.DeadlineExceeded) {
			return 0, errors.New("no answer in time")
		}
		return 0, errors.New("couldn't reach it")
	}
	resp.Body.Close()
	if resp.StatusCode == http.StatusTooManyRequests {
		wait := time.Second
		if v, err := strconv.ParseFloat(resp.Header.Get("Retry-After"), 64); err == nil && v > 0 {
			wait = time.Duration(v * float64(time.Second))
		}
		return min(wait, maxRetryAfter), errors.New("it answered HTTP 429 (rate limited)")
	}
	if resp.StatusCode/100 != 2 {
		return 0, fmt.Errorf("it answered HTTP %d", resp.StatusCode)
	}
	return 0, nil
}

// canaryAlertText is the alert for one touch: names, address and time only.
func canaryAlertText(h store.CanaryTouch) string {
	verb := map[string]string{"read": "was read", "write": "was written", "status": "had its status set",
		"flag": "was flagged", "note": "got a note"}[h.Action]
	if verb == "" {
		verb = "was touched"
	}
	msg := fmt.Sprintf("keydrop: canary `%s` %s by token `%s` from %s at %s.", h.Ref(), verb, h.Token, orUnknown(h.IP), h.At.UTC().Format(time.RFC3339))
	if h.TokenRevoked {
		msg += " The token was revoked."
	}
	return msg
}

func orUnknown(s string) string {
	if s == "" {
		return "an unknown address"
	}
	return s
}

// canaryTouched handles the side effects of an agent touching a canary,
// after the touch itself (and its Inbox entry) is stored: the log, and
// the alert.
func (s *Server) canaryTouched(r *http.Request, h store.CanaryTouch) {
	if h.Action != "read" { // a read has its own entry, secret.read.canary
		s.event(r, "token:"+h.Token, "secret.canary.touch", h.Ref(), h.Action)
	}
	if h.TokenRevoked {
		s.event(r, "system", "token.revoke", h.Token, "touched canary "+h.Ref())
	}
	if s.alerts.allow(h.Ref()+"\x00"+h.Token, s.now()) {
		s.alerts.send(canaryAlertText(h))
	}
}

func (s *Server) agentCtx(r *http.Request, t store.Token) store.AgentCtx {
	return store.AgentCtx{Token: t.Name, IP: s.clientIP(r)}
}

func (s *Server) handleSetCanary(w http.ResponseWriter, r *http.Request, _ string, se *session) {
	ns, name := r.PathValue("ns"), r.PathValue("name")
	on := r.PostFormValue("on") == "yes"
	switch err := s.store.SetCanary(ns, name, on); {
	case errors.Is(err, store.ErrNotFound):
		s.message(w, r, http.StatusNotFound, "Not found", "There's no secret called "+ns+"/"+name+".")
		return
	case err != nil:
		s.renderSecret(w, r, se, http.StatusBadRequest, err.Error())
		return
	}
	detail := "off"
	if on {
		detail = "on"
	}
	s.event(r, "admin", "secret.canary", ns+"/"+name, detail)
	s.back(w, r, "canary")
}

func (s *Server) handleDismissCanary(w http.ResponseWriter, r *http.Request, _ string, se *session) {
	if err := s.store.DismissCanaryHit(r.PathValue("id")); err != nil {
		s.renderInbox(w, r, se, http.StatusNotFound, "That canary alert is already dismissed.")
		return
	}
	http.Redirect(w, r, "/inbox?msg=dismissed", http.StatusSeeOther)
}

func (s *Server) handleCanarySettings(w http.ResponseWriter, r *http.Request, _ string, se *session) {
	on := r.PostFormValue("revoke") == "yes"
	if err := s.store.SetRevokeOnCanary(on); err != nil {
		s.renderSettings(w, r, se, http.StatusInternalServerError, err.Error())
		return
	}
	detail := "revoke on read off"
	if on {
		detail = "revoke on read on"
	}
	s.event(r, "admin", "settings.canary", "", detail)
	http.Redirect(w, r, "/settings?msg=canarysettings", http.StatusSeeOther)
}

// handleAlertTest sends a test alert now and shows the webhook's answer.
func (s *Server) handleAlertTest(w http.ResponseWriter, r *http.Request, _ string, se *session) {
	if !s.alerts.configured() {
		s.renderSettings(w, r, se, http.StatusBadRequest, "No alert webhook is configured: add one below.")
		return
	}
	err := s.alerts.test("keydrop: test alert, sent from Settings at " + s.now().UTC().Format(time.RFC3339) + ".")
	s.alerts.destination(true)
	if err != nil {
		s.event(r, "admin", "alert.test", "", "failed: "+err.Error())
		s.renderSettings(w, r, se, http.StatusBadGateway, "Test alert not delivered: "+err.Error()+".")
		return
	}
	s.event(r, "admin", "alert.test", "", "delivered")
	http.Redirect(w, r, "/settings?msg=alerttest", http.StatusSeeOther)
}

// handleAlertWebhook stores the webhook pasted in Settings. It's never
// shown again; Settings shows only where it posts.
func (s *Server) handleAlertWebhook(w http.ResponseWriter, r *http.Request, _ string, se *session) {
	raw := strings.TrimSpace(r.PostFormValue("webhook"))
	if raw == "" {
		s.renderSettings(w, r, se, http.StatusBadRequest, "Paste the webhook URL first.")
		return
	}
	u, err := url.Parse(raw)
	if err != nil || CheckAlertWebhook(raw) != nil || len(raw) > store.MaxWebhookLen {
		s.renderSettings(w, r, se, http.StatusBadRequest, "That isn't a webhook URL: it should start with https://.")
		return
	}
	if err := s.store.SetAlertWebhook(raw); err != nil {
		s.renderSettings(w, r, se, http.StatusInternalServerError, "Couldn't save the webhook: "+err.Error()+".")
		return
	}
	s.alerts.setURL(raw)
	s.alerts.destination(true)
	s.event(r, "admin", "settings.alertwebhook", "", "set ("+u.Hostname()+")")
	http.Redirect(w, r, "/settings?msg=webhookset", http.StatusSeeOther)
}

// handleAlertWebhookRemove forgets the webhook set in Settings; alerts go
// to KEYDROP_ALERT_WEBHOOK again, if that's set.
func (s *Server) handleAlertWebhookRemove(w http.ResponseWriter, r *http.Request, _ string, se *session) {
	if err := s.store.SetAlertWebhook(""); err != nil {
		s.renderSettings(w, r, se, http.StatusInternalServerError, "Couldn't remove the webhook: "+err.Error()+".")
		return
	}
	s.alerts.setURL(s.cfg.AlertWebhook)
	s.event(r, "admin", "settings.alertwebhook", "", "removed")
	http.Redirect(w, r, "/settings?msg=webhookremoved", http.StatusSeeOther)
}
