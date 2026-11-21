package server

import (
	"bytes"
	"context"
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
// work per read); only the admin's pages show it. A refused call on one
// records the touch, which the same call on an ordinary secret doesn't, so
// it can take longer: the probe is itself the touch (see the design doc).

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
	// noticeBurst and noticeRefill are the Inbox notices' own budget
	// (KEYDROP_ALERT_INBOX), smaller and separate, so no notice spends what
	// a canary alert needs. They're for what agents with a token cause:
	// requests, renewals, flags, expiry.
	noticeBurst  = 3
	noticeRefill = 2 * time.Minute
	// pairBurst and pairRefill are pairing notices' budget, separate again:
	// pairing needs no credential, so anyone on the network can cause
	// them, and they mustn't spend or block what agents' notices need.
	pairBurst  = 2
	pairRefill = 5 * time.Minute
	// alertQueue is how many security alerts may wait to be sent. Notices
	// wait in a queue of their own, half its size, which pairing notices
	// may fill only half of, so agents' notices always have room. The
	// sender takes security alerts first.
	alertQueue = 32
	// maxAlertKeys is how many keys the per-key limits hold before the
	// old ones are dropped. Notices are refused past it rather than grow
	// the map, and counted for their summary: pairing notices' keys come
	// from addresses anyone can pick, so they have a map of their own.
	maxAlertKeys = 10000
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
	queue  chan queued // security alerts; the body is built when posted
	noteQ  chan queued // Inbox notices, sent after any security alert
	once   sync.Once
	wg     sync.WaitGroup // alerts queued and not yet sent, for tests
	// flushEvery is how often run sends the summaries of what was held
	// back: alertRefill, so each has budget; tests make it shorter.
	flushEvery time.Duration

	mu         sync.Mutex
	url        string               // set with setURL; read with webhook
	format     string               // KEYDROP_ALERT_FORMAT; "" is auto
	dest       alertDest            // where url posts, for Settings
	last       map[string]time.Time // canary ref + token -> last alert
	lastNotice map[string]time.Time // kind + token -> last notice
	lastPair   map[string]time.Time // address group -> last pairing notice
	budget     bucket               // security alerts and Send test alert
	notices    bucket               // Inbox notices, never the other way round
	pairs      bucket               // pairing notices, never the other way round
	held       int                  // alerts over the budget, for the next summary
	heldNotice int                  // notices over theirs, for their own summary
	heldPair   int                  // pairing notices over theirs, likewise
	sleep      func(time.Duration)
}

// queued is a message waiting for the sender. done, if set, is told on
// the sender's goroutine whether it was delivered, before the message
// counts as sent (wg).
type queued struct {
	text string
	done func(delivered bool)
}

// bucket is a token bucket: burst at once, then one per refill.
type bucket struct {
	burst  float64
	refill time.Duration
	tokens float64
	filled time.Time
}

// take spends one, if there is one. Needs the alerter's mu.
func (b *bucket) take(now time.Time) bool {
	if !b.filled.IsZero() {
		b.tokens = min(b.burst, b.tokens+float64(now.Sub(b.filled))/float64(b.refill))
	}
	b.filled = now
	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
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
		now:        time.Now,
		queue:      make(chan queued, alertQueue),
		noteQ:      make(chan queued, alertQueue/2),
		flushEvery: alertRefill,
		last:       map[string]time.Time{},
		lastNotice: map[string]time.Time{},
		lastPair:   map[string]time.Time{},
		budget:     bucket{burst: alertBurst, refill: alertRefill, tokens: alertBurst},
		notices:    bucket{burst: noticeBurst, refill: noticeRefill, tokens: noticeBurst},
		pairs:      bucket{burst: pairBurst, refill: pairRefill, tokens: pairBurst},
		sleep:      time.Sleep,
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

// setURL changes where alerts go, including those already queued: their
// body is built when posted, so it has the new URL's format. The
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
	ok, _ := allowIn(a.last, key, now, false)
	return ok
}

// noticeClass is a kind of Inbox notice: pairing notices, which anyone on
// the network can cause, or agents' notices.
type noticeClass bool

const (
	agentNotice noticeClass = false
	pairNotice  noticeClass = true
)

// limits are the class's dedupe map, budget, count of what was held back
// and share of the notice queue. Needs a.mu.
func (a *alerter) limits(c noticeClass) (map[string]time.Time, *bucket, *int, int) {
	if c == pairNotice {
		return a.lastPair, &a.pairs, &a.heldPair, cap(a.noteQ) / 2
	}
	return a.lastNotice, &a.notices, &a.heldNotice, cap(a.noteQ)
}

// allowNotice is allow for Inbox notices, in their class's own map. One
// refused only because the map is full is counted for the summary.
func (a *alerter) allowNotice(c noticeClass, key string, now time.Time) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	m, _, held, _ := a.limits(c)
	ok, full := allowIn(m, key, now, true)
	if full {
		*held++
	}
	return ok
}

// allowIn reports whether key may have an alert now, and if so counts it
// in m. full: refused only because m is bounded and full. Needs a.mu.
func allowIn(m map[string]time.Time, key string, now time.Time, bounded bool) (ok, full bool) {
	if last, ok := m[key]; ok && now.Sub(last) < alertEvery {
		return false, false
	}
	if len(m) > maxAlertKeys {
		for k, t := range m {
			if now.Sub(t) >= alertEvery {
				delete(m, k)
			}
		}
		if bounded && len(m) > maxAlertKeys {
			return false, true
		}
	}
	m[key] = now
	return true, false
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
	if !a.budget.take(a.now()) || !a.enqueue(a.queue, queued{text: content}) {
		a.held++
	}
}

// notice queues an Inbox notice of class c. It spends only its class's
// budget and waits in the notice queue, which the sender takes only when
// no security alert is waiting, so no number of notices can crowd out or
// queue ahead of a security alert. Pairing notices may fill only half of
// it, so no number of pairing requests can spend or crowd out an agent's
// notice. What's over is counted for one summary per class.
func (a *alerter) notice(c noticeClass, content string) { a.queueNotice(c, content, true, nil) }

// queueNotice is notice, and reports whether content was queued. Without
// count, what's over isn't counted for the summary: the caller keeps it
// and tries again later (the expiry digest). done, if set, is told
// whether a queued notice was delivered (see queued).
func (a *alerter) queueNotice(c noticeClass, content string, count bool, done func(bool)) bool {
	if !a.configured() {
		return false
	}
	a.once.Do(func() { go a.run() })
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.noticeRoom(c) && a.take(c) && a.enqueue(a.noteQ, queued{content, done}) {
		return true
	}
	if count {
		_, _, held, _ := a.limits(c)
		*held++
	}
	return false
}

func (a *alerter) take(c noticeClass) bool {
	_, b, _, _ := a.limits(c)
	return b.take(a.now())
}

// noticeRoom reports whether a notice of class c may be queued. Needs
// a.mu, which every enqueue holds, so the queue can't grow between check
// and send.
func (a *alerter) noticeRoom(c noticeClass) bool {
	_, _, _, room := a.limits(c)
	return len(a.noteQ) < room
}

// enqueue queues one message on q without blocking. Needs a.mu.
func (a *alerter) enqueue(q chan queued, m queued) bool {
	a.wg.Add(1)
	select {
	case q <- m:
		return true
	default:
		a.wg.Done()
		return false
	}
}

// run sends the queues, security alerts first, and every alertRefill a
// summary of what was held back, when the budget allows one. A security
// alert still waits for the message being posted when it arrives.
func (a *alerter) run() {
	tick := time.NewTicker(a.flushEvery)
	defer tick.Stop()
	for {
		var m queued
		select {
		case m = <-a.queue:
		default:
			select {
			case m = <-a.queue:
			case m = <-a.noteQ:
			case <-tick.C:
				a.flushHeld()
				continue
			}
		}
		err := a.post(m.text)
		if err != nil {
			log.Printf("alert webhook: %v", err)
		}
		if m.done != nil {
			m.done(err == nil)
		}
		a.wg.Done()
	}
}

// flushHeld sends one summary of the alerts held back, and one of each
// class of notices held back, each when its own budget has room.
func (a *alerter) flushHeld() {
	a.mu.Lock()
	defer a.mu.Unlock()
	now := a.now()
	if a.held > 0 && a.budget.take(now) &&
		a.enqueue(a.queue, queued{text: fmt.Sprintf("keydrop: %d more alerts were held back by the rate limit; see keydrop's Inbox and audit log.", a.held)}) {
		a.held = 0
	}
	things := "things are"
	if a.heldNotice == 1 {
		things = "thing is"
	}
	if a.heldNotice > 0 && a.noticeRoom(agentNotice) && a.notices.take(now) &&
		a.enqueue(a.noteQ, queued{text: fmt.Sprintf("keydrop: %d more %s waiting for you; see keydrop's Inbox and Agents page.", a.heldNotice, things)}) {
		a.heldNotice = 0
	}
	machines := "machines"
	if a.heldPair == 1 {
		machines = "machine"
	}
	if a.heldPair > 0 && a.noticeRoom(pairNotice) && a.pairs.take(now) &&
		a.enqueue(a.noteQ, queued{text: fmt.Sprintf("keydrop: %d more %s asked to pair; see keydrop's Agents page.", a.heldPair, machines)}) {
		a.heldPair = 0
	}
}

func (a *alerter) post(content string) error {
	for try := 0; ; try++ {
		wait, err := a.postOnce(content)
		if wait == 0 || try >= alertRetries {
			return err
		}
		a.sleep(wait)
	}
}

// sendAs is the format alerts go out in now, for Settings and postOnce.
func (a *alerter) sendAs() (raw, format string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.url, resolveFormat(a.format, a.url)
}

// postOnce sends content once, in the current URL's format. On a 429 it
// returns how long to wait before trying again (the Retry-After, at most
// maxRetryAfter).
func (a *alerter) postOnce(content string) (time.Duration, error) {
	ctx, cancel := context.WithTimeout(context.Background(), alertTimeout)
	defer cancel()
	u, format := a.sendAs()
	if u == "" {
		return 0, errors.New("no webhook is configured")
	}
	body, ctype := alertBody(format, content)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u, bytes.NewReader(body))
	if err != nil {
		return 0, errors.New("couldn't build the request")
	}
	req.Header.Set("Content-Type", ctype)
	if format == formatText {
		req.Header.Set("Title", "keydrop") // ntfy's notification title
	}
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

// handleSetLimit sets which agents may use a key: any agent with its
// namespace ("only" is "no"), or only the ticked ones ("yes"), which must
// have the namespace. Anything else changes nothing: a form that lost its
// choice mustn't lift a limit. The log names the agents, never anything
// about the value.
func (s *Server) handleSetLimit(w http.ResponseWriter, r *http.Request, _ string, se *session) {
	ns, name := r.PathValue("ns"), r.PathValue("name")
	only := r.PostFormValue("only")
	var err error
	if only != "yes" && only != "no" {
		err = errors.New("choose which agents may use it: any agent with the namespace, or only the ones ticked. Nothing was changed")
	} else {
		err = s.store.SetLimit(ns, name, only == "yes", r.PostForm["token"])
	}
	switch {
	case errors.Is(err, store.ErrNotFound):
		s.message(w, r, http.StatusNotFound, "Not found", "There's no secret called "+ns+"/"+name+".")
		return
	case err != nil:
		s.renderSecret(w, r, se, http.StatusBadRequest, err.Error())
		return
	}
	detail := "any agent with the namespace"
	if sec, _ := s.store.GetSecret(ns, name); sec.Limit != nil {
		detail = "only: " + strings.Join(sec.Limit.Tokens, ", ")
		if len(sec.Limit.Tokens) == 0 {
			detail = "only: no agent"
		}
	}
	s.event(r, "admin", "secret.limit", ns+"/"+name, detail)
	s.back(w, r, "limit")
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
		s.renderSettings(w, r, se, http.StatusBadRequest, "That isn't a webhook URL: it should start with https:// (or http://).")
		return
	}
	if err := s.store.SetAlertWebhook(raw); err != nil {
		s.renderSettings(w, r, se, http.StatusInternalServerError, "Couldn't save the webhook: "+err.Error()+".")
		return
	}
	s.alerts.setURL(raw)
	s.alerts.destination(true)
	s.kickExpiry() // keys held back for want of a webhook
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
