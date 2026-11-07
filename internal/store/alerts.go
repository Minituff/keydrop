package store

import (
	"errors"
	"time"
)

// The alert webhook set in Settings. It came in the release after MAC4:
// the alerts field and MAC5 are outside v4View, so that release still
// opens a file with it, ignores it, and alerts go to KEYDROP_ALERT_WEBHOOK
// as before. It doesn't restrict access, so unlike the MAC4 fields it isn't
// tied to the key check: deleting it together with MAC5 gives a file that
// release could have written, and the server falls back to the variable.

// AlertSettings is the webhook set in Settings, sealed under the master
// key. The URL is a credential: it's never returned to the admin.
type AlertSettings struct {
	Webhook []byte    `json:"webhook"`
	SetAt   time.Time `json:"set_at"`
}

const (
	alertWebhookAAD = "settings/alert-webhook"
	// MaxWebhookLen bounds a webhook URL set in Settings.
	MaxWebhookLen = 2048
)

// AlertWebhook returns the webhook set in Settings and when, or "" if none
// is.
func (s *Store) AlertWebhook() (string, time.Time, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.st.Alerts == nil {
		return "", time.Time{}, nil
	}
	pt, err := s.open(s.st.Alerts.Webhook, alertWebhookAAD)
	if err != nil {
		return "", time.Time{}, errors.New("the alert webhook in keydrop.json can't be decrypted")
	}
	return string(pt), s.st.Alerts.SetAt, nil
}

// SetAlertWebhook stores the webhook, or removes it when url is "". The
// caller checks it's a URL; this only bounds its size.
func (s *Store) SetAlertWebhook(url string) error {
	if len(url) > MaxWebhookLen {
		return errors.New("the webhook URL is too long")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	snap := s.st.clone()
	if url == "" {
		s.st.Alerts = nil
	} else {
		s.st.Alerts = &AlertSettings{Webhook: s.seal([]byte(url), alertWebhookAAD), SetAt: s.now().UTC()}
	}
	return s.commit(snap)
}
