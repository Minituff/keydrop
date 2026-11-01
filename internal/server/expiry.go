package server

import (
	"errors"
	"fmt"
	"math"
	"net/http"
	"strconv"
	"time"

	"github.com/minituff/keydrop/internal/audit"
	"github.com/minituff/keydrop/internal/store"
)

// Token expiry and renewal. An agent asks for its own token to be renewed
// (keydrop renew); the admin approves it in the Inbox, which replaces the
// token with a new one; the agent collects that with its old token, once,
// from an allowed address. Pairing and this are the only ways a token is
// handed over.

// renewalsPerHour is how many renewal requests and status checks one token
// may make an hour from one address (keydrop renew --wait polls), and
// collectsPerHour how many collects: a separate budget, so asking can't
// use up collecting.
const (
	renewalsPerHour = 240
	collectsPerHour = 30
)

// staleAfter is how long unused before the Agents page points a token out.
const staleAfter = 30 * 24 * time.Hour

// formLifetime reads the lifetime field (days, "0" for never); empty is
// the default.
func formLifetime(r *http.Request) (int, error) {
	v := r.PostFormValue("lifetime")
	if v == "" {
		return store.DefaultTokenLifetime, nil
	}
	d, err := strconv.Atoi(v)
	if err != nil {
		return 0, store.ErrBadLifetime
	}
	return d, store.CheckLifetime(d)
}

func lifetimeLabel(days int) string {
	if days == 0 {
		return "never expires"
	}
	return fmt.Sprintf("%d days", days)
}

// expiryText is how the UI shows a token's expiry.
func expiryText(t *time.Time, now time.Time) string {
	switch {
	case t == nil:
		return "no expiry"
	case !now.Before(*t):
		return "expired " + t.UTC().Format("2006-01-02")
	}
	return "expires in " + daysText(int(math.Ceil(t.Sub(now).Hours()/24)))
}

func daysText(n int) string {
	if n == 1 {
		return "1 day"
	}
	return fmt.Sprintf("%d days", n)
}

// tokenView is a token as the Agents page and the Inbox show it.
type tokenView struct {
	store.Token
	Expiry  string
	Expired bool
	Soon    bool // within 14 days
	// Stale: not used for staleAfter (or, never used, made that long ago).
	Stale     bool
	StaleDays int
	// OtherIP: the renewal was asked from somewhere other than where the
	// token was last used. Could be a stolen token; the Inbox says so.
	OtherIP bool
}

func (s *Server) tokenViews() []tokenView {
	now := s.now()
	var out []tokenView
	for _, t := range s.store.ListTokens() {
		v := tokenView{Token: t, Expiry: expiryText(t.ExpiresAt, now), Expired: t.Expired(now)}
		v.Soon = !v.Expired && t.ExpiresAt != nil && t.ExpiresAt.Sub(now) < 30*24*time.Hour
		last := t.CreatedAt
		if t.LastUsedAt != nil {
			last = *t.LastUsedAt
		}
		if d := now.Sub(last); d >= staleAfter {
			v.Stale, v.StaleDays = true, int(d.Hours()/24)
		}
		out = append(out, v)
	}
	return out
}

// renewalViews are the tokens with a renewal request, or an approved one
// waiting to be collected, for the Inbox.
func (s *Server) renewalViews() (asked, collecting []tokenView) {
	for _, v := range s.tokenViews() {
		switch {
		case v.Rotation != nil:
			collecting = append(collecting, v)
		case v.Renewal != nil:
			v.OtherIP = v.LastUsedFrom != "" && v.Renewal.IP != v.LastUsedFrom
			asked = append(asked, v)
		}
	}
	return asked, collecting
}

// sweepRotations revokes tokens whose renewal wasn't collected in time.
func (s *Server) sweepRotations(now time.Time) {
	for _, name := range s.store.RevokeUncollectedRotations(now) {
		s.audit.Add(audit.Event{Actor: "keydrop", Action: "token.revoke", Target: name, Detail: "approved renewal never collected"})
	}
}

// ---- agent side ----

// renewState is what an agent learns about its own renewal.
func renewState(t store.Token, now time.Time) map[string]any {
	out := map[string]any{"name": t.Name, "expires_at": t.ExpiresAt, "expired": t.Expired(now)}
	switch {
	case t.Rotation != nil:
		out["state"] = "approved" // collect it: POST /api/v1/token/collect
		out["collect_by"] = t.Rotation.CollectBy
	case t.Renewal != nil:
		out["state"] = "pending"
		out["requested_at"] = t.Renewal.At
	case t.ExpiresAt == nil:
		out["state"] = "never"
	default:
		out["state"] = "none"
	}
	return out
}

func (s *Server) renewLimited(w http.ResponseWriter, r *http.Request, l *rateLimit, t store.Token) bool {
	if !l.allow(t.Name+"\x00"+s.clientIP(r), s.now()) {
		apiError(w, http.StatusTooManyRequests, "too many renewal calls from this token; try again later")
		return true
	}
	return false
}

// apiRenew asks the admin to renew the calling token. Asking again while a
// request is pending changes nothing and says so.
func (s *Server) apiRenew(w http.ResponseWriter, r *http.Request, t store.Token) {
	s.sweepRotations(s.now())
	if s.renewLimited(w, r, s.renewals, t) {
		return
	}
	_, created, err := s.store.RequestRenewal(t.Name, s.clientIP(r))
	switch {
	case errors.Is(err, store.ErrNoExpiry), errors.Is(err, store.ErrRotated):
		// Nothing to ask for: it never expires, or it's already approved.
	case errors.Is(err, store.ErrNotFound):
		apiError(w, http.StatusUnauthorized, "invalid token")
		return
	case err != nil:
		apiError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if created {
		s.event(r, actor(t), "token.renewal.request", t.Name, "expires "+expiresHeader(t.ExpiresAt))
	}
	cur, _ := tokenNamed(s.store.ListTokens(), t.Name)
	out := renewState(cur, s.now())
	out["created"] = created
	writeJSON(w, http.StatusOK, out)
}

// apiRenewStatus says where the calling token's renewal stands.
func (s *Server) apiRenewStatus(w http.ResponseWriter, r *http.Request, t store.Token) {
	if s.renewLimited(w, r, s.renewals, t) {
		return
	}
	writeJSON(w, http.StatusOK, renewState(t, s.now()))
}

// apiCollect hands over the token that replaces the calling one. The caller
// authenticated with the old token from an allowed address (see
// agentRenewal), and must be at the address that asked for the renewal.
// It can be repeated until the new token is first used, in case an answer
// was lost; after that only the new token works.
func (s *Server) apiCollect(w http.ResponseWriter, r *http.Request, t store.Token) {
	if s.renewLimited(w, r, s.collects, t) {
		return
	}
	ip := s.clientIP(r)
	plain, nt, err := s.store.CollectRotation(t, ip)
	switch {
	case errors.Is(err, store.ErrNotFound):
		apiError(w, http.StatusNotFound, "there's no renewed token to collect: the renewal wasn't approved, or the new token is already in use")
		return
	case errors.Is(err, store.ErrCollectIP):
		// Someone else holding the old token, most likely: refuse, log, and
		// tell the admin.
		s.event(r, actor(t), "token.collect.refused", t.Name, "collect from an address other than the one that asked for the renewal")
		if s.alerts.allow("collect\x00"+t.Name, s.now()) {
			s.alerts.send(fmt.Sprintf("keydrop: token `%s` tried to collect its renewed token from %s, not the address that asked for the renewal. Refused. If that wasn't the agent, revoke the token.", t.Name, orUnknown(ip)))
		}
		apiError(w, http.StatusForbidden, err.Error())
		return
	case err != nil:
		apiError(w, http.StatusInternalServerError, "couldn't hand over the new token; check keydrop's log")
		return
	}
	if t.Rotation.Collected == nil {
		s.event(r, actor(t), "token.collect", t.Name, "renewed token collected, expires "+expiresHeader(nt.ExpiresAt))
	} else {
		s.event(r, actor(t), "token.collect", t.Name, "renewed token collected again")
	}
	writeJSON(w, http.StatusOK, map[string]any{"token": plain, "name": nt.Name, "namespaces": nt.Namespaces, "expires_at": nt.ExpiresAt})
}

// ---- admin side ----

// handleRenewToken renews a token: from the Inbox (approving the agent's
// request) or the Agents page. Either way it replaces the token, for the
// agent to collect.
func (s *Server) handleRenewToken(w http.ResponseWriter, r *http.Request, _ string, se *session) {
	name := r.PathValue("name")
	back := "/tokens"
	if r.PostFormValue("back") == "inbox" {
		back = "/inbox"
	}
	days, err := formLifetime(r)
	if err != nil {
		s.renderTokens(w, r, se, http.StatusBadRequest, "Lifetime: "+err.Error()+".")
		return
	}
	old, ok := tokenNamed(s.store.ListTokens(), name)
	if !ok {
		s.renderTokens(w, r, se, http.StatusNotFound, "There's no agent called "+name+".")
		return
	}
	rot, err := s.store.RotateToken(name, days)
	if err != nil {
		s.renderTokens(w, r, se, http.StatusInternalServerError, err.Error())
		return
	}
	action := "token.renew"
	if old.Renewal != nil {
		action = "token.renewal.approve"
	}
	s.event(r, "admin", action, name, lifetimeLabel(days)+", new token to collect by "+rot.CollectBy.UTC().Format("2006-01-02"))
	http.Redirect(w, r, back+"?msg=renewed", http.StatusSeeOther)
}

func (s *Server) handleDeclineRenewal(w http.ResponseWriter, r *http.Request, _ string, se *session) {
	name := r.PathValue("name")
	if err := s.store.DeclineRenewal(name); err != nil {
		s.renderInbox(w, r, se, http.StatusNotFound, "There's no renewal request from "+name+" any more.")
		return
	}
	s.event(r, "admin", "token.renewal.decline", name, "")
	http.Redirect(w, r, "/inbox?msg=declined", http.StatusSeeOther)
}
