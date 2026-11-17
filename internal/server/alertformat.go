package server

import (
	"encoding/json"
	"errors"
	"net/url"
	"strings"
)

// Alert formats (KEYDROP_ALERT_FORMAT): the shape of the webhook's body.
// The alert texts are written once, with Discord/Slack-style backticks
// around names; alertBody adapts them to the format.
const (
	formatAuto    = "auto"
	formatDiscord = "discord"
	formatSlack   = "slack"
	formatText    = "text"
)

// CheckAlertFormat validates KEYDROP_ALERT_FORMAT. The value isn't
// repeated, in case the webhook URL was pasted into the wrong variable.
func CheckAlertFormat(f string) error {
	switch f {
	case "", formatAuto, formatDiscord, formatSlack, formatText:
		return nil
	}
	return errors.New("KEYDROP_ALERT_FORMAT must be auto, discord, slack or text (its value isn't shown here)")
}

// resolveFormat is the format alerts to raw are sent in. auto picks Slack
// only for Slack's own webhook host and otherwise keeps the Discord body
// every earlier release sent. It never guesses ntfy: self-hosted ntfy can
// be on any host, and a wrong guess would silently break a receiver that
// takes the Discord body.
func resolveFormat(format, raw string) string {
	if format != "" && format != formatAuto {
		return format
	}
	if u, err := url.Parse(raw); err == nil && u.Scheme == "https" && strings.EqualFold(u.Hostname(), "hooks.slack.com") {
		return formatSlack
	}
	return formatDiscord
}

// slackEscape makes the control characters of Slack's markup literal, so
// nothing in an alert becomes a mention (<!channel>, <@U…>) or a link.
// Token and namespace names ([a-z0-9._-]) and secret names ([A-Z0-9_])
// can't hold them, but an address can: an IPv6 zone in X-Forwarded-For
// from a trusted proxy is free text (fe80::1%<!channel>), and pairing needs
// no credential. Escaped whatever the source.
var slackEscape = strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;")

// alertBody builds the request body and its Content-Type for one alert.
func alertBody(format, content string) ([]byte, string) {
	switch format {
	case formatSlack:
		b, _ := json.Marshal(map[string]string{"text": slackEscape.Replace(content)})
		return b, "application/json"
	case formatText:
		// ntfy and other plain receivers: no markup to render.
		return []byte(strings.ReplaceAll(content, "`", "")), "text/plain; charset=utf-8"
	}
	// No mentions: the content names tokens and secrets, which mustn't
	// ping anyone.
	b, _ := json.Marshal(map[string]any{"content": content, "allowed_mentions": map[string]any{"parse": []string{}}})
	return b, "application/json"
}

// formatName is how Settings names a resolved format.
var formatName = map[string]string{formatDiscord: "Discord", formatSlack: "Slack", formatText: "plain text"}
