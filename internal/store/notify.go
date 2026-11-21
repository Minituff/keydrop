package store

import (
	"errors"
	"slices"
)

// The notification settings chosen in Settings. They came in the release
// after MAC6 (v0.1.3): notify and MAC7 are outside v6View, so that release
// still opens a file with them, ignores them, Inbox alerts follow
// KEYDROP_ALERT_INBOX as before and expiry alerts are off. They neither grant nor restrict access, so
// like the webhook they aren't tied to the key check: deleting notify
// together with MAC7 gives a file that release could have written, and the
// server falls back to the variable (and to no expiry alerts). Whoever can write the data directory
// can already do as much by deleting the whole file; MAC7 stops them
// changing a choice, or adding one, without the master key.

// NotifySettings is what the admin chose for notifications. Each field
// is its zero value until a choice is made.
type NotifySettings struct {
	// Inbox turns Inbox alerts on or off, whatever KEYDROP_ALERT_INBOX says.
	Inbox *bool `json:"inbox,omitempty"`
	// ExpiryDays is how many days before a key's expiry date the alert
	// webhook is told about it; 0 is off. One of ExpiryAlertChoices.
	ExpiryDays int `json:"expiry_days,omitempty"`
}

// ExpiryAlertChoices are the warning windows Settings offers, in days.
var ExpiryAlertChoices = []int{7, 14, 30}

// ErrBadExpiryDays: not off and not one of ExpiryAlertChoices.
var ErrBadExpiryDays = errors.New("choose off, 7, 14 or 30 days")

// zero reports whether nothing is chosen, so nothing needs storing. A new
// field goes here and in clone too.
func (n NotifySettings) zero() bool { return n.Inbox == nil && n.ExpiryDays == 0 }

func (n NotifySettings) clone() NotifySettings {
	if n.Inbox != nil {
		v := *n.Inbox
		n.Inbox = &v
	}
	return n
}

// InboxAlerts returns the Inbox alerts choice made in Settings, and whether
// one was made. Without one, KEYDROP_ALERT_INBOX decides.
func (s *Store) InboxAlerts() (on, chosen bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.st.Notify == nil || s.st.Notify.Inbox == nil {
		return false, false
	}
	return *s.st.Notify.Inbox, true
}

// SetInboxAlerts stores the admin's choice; nil forgets it, so
// KEYDROP_ALERT_INBOX decides again.
func (s *Store) SetInboxAlerts(on *bool) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	snap := s.st.clone()
	var n NotifySettings
	if s.st.Notify != nil {
		n = s.st.Notify.clone()
	}
	n.Inbox = nil
	if on != nil {
		v := *on
		n.Inbox = &v
	}
	return s.setNotify(snap, n)
}

// ExpiryAlertDays returns the expiry warning window in days; 0 is off.
func (s *Store) ExpiryAlertDays() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.st.Notify == nil {
		return 0
	}
	return s.st.Notify.ExpiryDays
}

// SetExpiryAlertDays stores the expiry warning window: 0 (off) or one of
// ExpiryAlertChoices.
func (s *Store) SetExpiryAlertDays(days int) error {
	if days != 0 && !slices.Contains(ExpiryAlertChoices, days) {
		return ErrBadExpiryDays
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	snap := s.st.clone()
	var n NotifySettings
	if s.st.Notify != nil {
		n = s.st.Notify.clone()
	}
	n.ExpiryDays = days
	return s.setNotify(snap, n)
}

// setNotify stores n, or nothing when it's all defaults. Needs s.mu.
func (s *Store) setNotify(snap state, n NotifySettings) error {
	if n.zero() {
		s.st.Notify = nil // the default: store nothing
	} else {
		s.st.Notify = &n
	}
	return s.commit(snap)
}
