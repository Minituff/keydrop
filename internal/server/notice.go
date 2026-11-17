package server

import (
	"fmt"
	"net/http"
	"strings"
)

// Inbox alerts (Settings, or KEYDROP_ALERT_INBOX until a choice is made
// there): a short notice to the alert webhook when something starts
// waiting for the admin, so an agent blocked on `keydrop wait` isn't
// waiting on an Inbox nobody is looking at.
//
// A notice is built by the server from names and addresses only: never a
// value or token, and never text an agent or a pairing client wrote (a
// request's description, a flag's reason or link, a pairing's claimed host
// and user), which is untrusted and for the admin's pages only. Nor the
// pairing code: the admin compares the code on the page with the one on
// the agent's terminal, and the webhook channel mustn't be a third source.

// inboxAlertsOn reports whether Inbox alerts are on, and whether that was
// chosen in Settings: the admin's choice there wins once made, on or off,
// as a webhook added there does; until then KEYDROP_ALERT_INBOX decides.
func (s *Server) inboxAlertsOn() (on, chosen bool) {
	if on, chosen := s.store.InboxAlerts(); chosen {
		return on, true
	}
	return s.cfg.AlertInbox, false
}

func inboxSource(chosen bool) string {
	if chosen {
		return "set in Settings"
	}
	return "KEYDROP_ALERT_INBOX"
}

// inboxNotice sends text, ended with a link to path when
// KEYDROP_PUBLIC_URL is configured, at most once per key per alertEvery.
// Call it only after the change it announces was stored.
func (s *Server) inboxNotice(key, text, path, page string) {
	if on, _ := s.inboxAlertsOn(); !on || !s.alerts.configured() {
		return
	}
	if !s.alerts.allowNotice(key, s.now()) {
		return
	}
	if s.cfg.PublicURL != "" && !s.cfg.PublicURLGuess {
		text += ": " + strings.TrimRight(s.cfg.PublicURL, "/") + path
	} else {
		text += ". Open keydrop's " + page + "."
	}
	s.alerts.notice(text)
}

func (s *Server) noticePairing(ip, id string) {
	s.inboxNotice("pair\x00"+sourceGroup(ip),
		fmt.Sprintf("keydrop: a machine at %s is asking to pair. Check its code before approving", orUnknown(ip)),
		"/pair/"+id, "Agents page")
}

func (s *Server) noticeRequest(token, ns string, names []string) {
	text := fmt.Sprintf("keydrop: `%s` is asking for `%s/%s`. Fill it in", token, ns, names[0])
	if len(names) > 1 {
		text = fmt.Sprintf("keydrop: `%s` is asking for %d keys in `%s`. Fill them in", token, len(names), ns)
	}
	s.inboxNotice("request\x00"+token, text, "/inbox", "Inbox")
}

func (s *Server) noticeRenewal(token string) {
	s.inboxNotice("renew\x00"+token,
		fmt.Sprintf("keydrop: `%s` is asking for its new token. Approve or decline", token), "/inbox", "Inbox")
}

func (s *Server) noticeFlag(token, ref string) {
	s.inboxNotice("flag\x00"+token, fmt.Sprintf("keydrop: `%s` flagged `%s`. See why", token, ref), "/inbox", "Inbox")
}

// handleAlertInbox turns Inbox alerts on or off, or ("default") forgets the
// choice so KEYDROP_ALERT_INBOX decides again.
func (s *Server) handleAlertInbox(w http.ResponseWriter, r *http.Request, _ string, se *session) {
	var choice *bool
	switch r.PostFormValue("inbox") {
	case "on":
		on := true
		choice = &on
	case "off":
		off := false
		choice = &off
	case "default":
	default:
		s.renderSettings(w, r, se, http.StatusBadRequest, "Choose on, off or the default for Inbox alerts.")
		return
	}
	if err := s.store.SetInboxAlerts(choice); err != nil {
		s.renderSettings(w, r, se, http.StatusInternalServerError, "Couldn't save the Inbox alerts setting: "+err.Error()+".")
		return
	}
	detail := onOff(s.cfg.AlertInbox) + " (the default, from KEYDROP_ALERT_INBOX)"
	if choice != nil {
		detail = onOff(*choice)
	}
	s.event(r, "admin", "settings.alertinbox", "", detail)
	http.Redirect(w, r, "/settings?msg=alertinbox", http.StatusSeeOther)
}
