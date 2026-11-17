package server

import (
	"context"
	"fmt"
	"net/http"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/minituff/keydrop/internal/store"
)

// Expiry alerts (Settings: "Warn me before a key expires"): one digest to
// the alert webhook when keys with an expiry date come within the chosen
// number of days of it, and one more when they pass it, so the first sign
// of an expired API key isn't an agent's job failing.
//
// What's been announced is kept in memory only: a record in the state
// file would be a new field to MAC and migrate for something that grants
// nothing. After a restart keys already in the window are announced once
// more. A digest names keys and how far off their dates are, built here:
// never a value, and never a description, usage or anything an agent wrote.

const (
	expiryFirstCheck = time.Minute // after start, so the startup log comes first
	expiryCheckEvery = time.Hour
	maxExpiryNames   = 8 // named in one digest; the rest are counted
)

// expiryMark is what's been announced for a key: its date then, and
// whether it was in the window (expirySoon) or past it (expiryPast).
type expiryMark struct {
	expires time.Time
	stage   int
}

const (
	expirySoon = 1
	expiryPast = 2
)

// RunBackground runs the server's periodic work until ctx is done: the
// expiry check shortly after start, then hourly, and soon after its
// setting or the webhook changes.
func (s *Server) RunBackground(ctx context.Context) {
	s.runExpiryChecks(ctx, expiryFirstCheck, expiryCheckEvery)
}

func (s *Server) runExpiryChecks(ctx context.Context, first, every time.Duration) {
	t := time.NewTimer(first)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			t.Reset(every)
		case <-s.expiryKick:
		}
		s.checkExpiry()
	}
}

// kickExpiry asks the background loop for a check now, if it's running.
func (s *Server) kickExpiry() {
	select {
	case s.expiryKick <- struct{}{}:
	default:
	}
}

// checkExpiry sends one digest of the keys that newly entered the warning
// window or newly passed their date. A key is announced again only after
// its date changes, or after it leaves the window and comes back.
func (s *Server) checkExpiry() {
	s.expiryMu.Lock()
	defer s.expiryMu.Unlock()
	days := s.store.ExpiryAlertDays()
	if days == 0 {
		s.expiryMarks = nil // turned on again, it starts afresh
		return
	}
	if !s.alerts.configured() {
		return // nothing marked: announced once a webhook is added
	}
	now := s.now()
	window := now.Add(time.Duration(days) * 24 * time.Hour)
	marks := map[string]expiryMark{}
	var due []store.Secret
	for _, sec := range s.store.ListSecrets(func(sec *store.Secret) bool {
		// Secrets and variables with a value: a pending request has none
		// to expire. Not canaries: a decoy's date is there to look real
		// to agents, and nobody renews a decoy.
		return sec.Expires != nil && len(sec.Value) > 0 && !sec.Canary && sec.Expires.Before(window)
	}) {
		m := expiryMark{*sec.Expires, expirySoon}
		if !now.Before(m.expires) {
			m.stage = expiryPast
		}
		if old, ok := s.expiryMarks[sec.Ref()]; ok && old.expires.Equal(m.expires) && old.stage >= m.stage {
			marks[sec.Ref()] = old
			continue
		}
		marks[sec.Ref()] = m
		due = append(due, sec)
	}
	// Notices' budget and half the queue, never the security alerts'. If
	// it isn't queued, nothing is marked and the next check tries again.
	if len(due) > 0 && !s.alerts.queueNotice(s.expiryDigest(due, days, now), false) {
		return
	}
	s.expiryMarks = marks
}

// expiryDigest is the message for due, soonest (or longest expired) first.
func (s *Server) expiryDigest(due []store.Secret, days int, now time.Time) string {
	sort.SliceStable(due, func(i, j int) bool { return due[i].Expires.Before(*due[j].Expires) })
	soon, past := 0, 0
	var names []string
	for _, sec := range due {
		var when string
		if left := sec.Expires.Sub(now); left > 0 {
			soon++
			when = "in " + dayCount(left)
		} else {
			past++
			when = "expired " + dayCount(-left) + " ago"
			if -left < 24*time.Hour {
				when = "expired today"
			}
		}
		if len(names) < maxExpiryNames {
			names = append(names, fmt.Sprintf("`%s` (%s)", sec.Ref(), when))
		}
	}
	var parts []string
	if soon > 0 {
		parts = append(parts, fmt.Sprintf("%s within %d days", count(soon, "key expires", "keys expire"), days))
	}
	if past > 0 {
		parts = append(parts, count(past, "key has expired", "keys have expired"))
	}
	text := "keydrop: " + strings.Join(parts, " and ") + ": " + strings.Join(names, ", ")
	if more := len(due) - len(names); more > 0 {
		text += fmt.Sprintf(" and %d more", more)
	}
	renew := ". Renew them"
	if len(due) == 1 {
		renew = ". Renew it"
	}
	return s.withLink(text+renew, "/", "Secrets page")
}

func count(n int, one, many string) string {
	if n == 1 {
		return "1 " + one
	}
	return fmt.Sprintf("%d %s", n, many)
}

// dayCount is d in whole days, rounded down; under a day is "less than a day".
func dayCount(d time.Duration) string {
	if d < 24*time.Hour {
		return "less than a day"
	}
	return count(int(d/(24*time.Hour)), "day", "days")
}

// handleAlertExpiry sets how many days before a key's expiry date the
// webhook is told; 0 is off.
func (s *Server) handleAlertExpiry(w http.ResponseWriter, r *http.Request, _ string, se *session) {
	days, err := strconv.Atoi(r.PostFormValue("days"))
	if err != nil || (days != 0 && !slices.Contains(store.ExpiryAlertChoices, days)) {
		s.renderSettings(w, r, se, http.StatusBadRequest, "Choose off, 7, 14 or 30 days for expiry alerts.")
		return
	}
	if err := s.store.SetExpiryAlertDays(days); err != nil {
		s.renderSettings(w, r, se, http.StatusInternalServerError, "Couldn't save the expiry alerts setting: "+err.Error()+".")
		return
	}
	detail := "off"
	if days > 0 {
		detail = strconv.Itoa(days) + " days"
	}
	s.event(r, "admin", "settings.alertexpiry", "", detail)
	s.kickExpiry()
	http.Redirect(w, r, "/settings?msg=alertexpiry", http.StatusSeeOther)
}
