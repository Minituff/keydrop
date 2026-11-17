package server

import (
	"fmt"
	"strings"
)

// Inbox alerts (KEYDROP_ALERT_INBOX): a short notice to the alert webhook
// when something starts waiting for the admin, so an agent blocked on
// `keydrop wait` isn't waiting on an Inbox nobody is looking at.
//
// A notice is built by the server from names and addresses only: never a
// value or token, and never text an agent or a pairing client wrote (a
// request's description, a flag's reason or link, a pairing's claimed host
// and user), which is untrusted and for the admin's pages only. Nor the
// pairing code: the admin compares the code on the page with the one on
// the agent's terminal, and the webhook channel mustn't be a third source.

// inboxNotice sends text, ended with a link to path when
// KEYDROP_PUBLIC_URL is configured, at most once per key per alertEvery.
// Call it only after the change it announces was stored.
func (s *Server) inboxNotice(key, text, path, page string) {
	if !s.cfg.AlertInbox || !s.alerts.configured() {
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
