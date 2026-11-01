package server

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"
	"unicode"
)

// alertDest is where the webhook posts, as shown in Settings. Never the URL
// itself: its path is the credential.
type alertDest struct {
	Known bool // looked up (or tried to)
	Host  string
	// For a Discord webhook: its name, a link to its channel, and Problem
	// when Discord says it doesn't exist.
	Discord    bool
	Name       string
	ChannelURL string
	Problem    string
}

var (
	discordHosts = map[string]bool{"discord.com": true, "discordapp.com": true, "ptb.discord.com": true, "canary.discord.com": true}
	discordPath  = regexp.MustCompile(`^/api(/v\d+)?/webhooks/\d+/[A-Za-z0-9_-]+/?$`)
	discordID    = regexp.MustCompile(`^\d{1,20}$`)
)

// isDiscordWebhook reports whether u is a Discord webhook URL, which answers
// a GET with its name and channel.
func isDiscordWebhook(u *url.URL) bool {
	return u.Scheme == "https" && discordHosts[strings.ToLower(u.Hostname())] && u.Port() == "" && discordPath.MatchString(u.Path)
}

// parseDiscordWebhook reads Discord's answer to a GET on a webhook. The
// name is Discord's text, shown in the admin's page: cleaned and capped.
func parseDiscordWebhook(body []byte) (name, channelURL string, ok bool) {
	var w struct {
		Name      string `json:"name"`
		ChannelID string `json:"channel_id"`
		GuildID   string `json:"guild_id"`
	}
	if json.Unmarshal(body, &w) != nil {
		return "", "", false
	}
	name = strings.Map(func(r rune) rune {
		if unicode.IsControl(r) || unicode.Is(unicode.Cf, r) {
			return -1
		}
		return r
	}, w.Name)
	if r := []rune(name); len(r) > 80 {
		name = string(r[:80]) + "…"
	}
	if discordID.MatchString(w.ChannelID) && discordID.MatchString(w.GuildID) {
		channelURL = "https://discord.com/channels/" + w.GuildID + "/" + w.ChannelID
	}
	return name, channelURL, true
}

// destination returns where alerts go, looking it up the first time, or
// again with refresh (a GET on a Discord webhook, at most alertTimeout).
func (a *alerter) destination(refresh bool) alertDest {
	a.mu.Lock()
	u, d := a.url, a.dest
	a.mu.Unlock()
	if u == "" || (d.Known && !refresh) {
		return d
	}
	d = a.describe(u)
	a.mu.Lock()
	if a.url == u {
		a.dest = d
	}
	a.mu.Unlock()
	return d
}

func (a *alerter) describe(raw string) alertDest {
	u, err := url.Parse(raw)
	if err != nil {
		return alertDest{Known: true}
	}
	d := alertDest{Known: true, Host: u.Hostname()}
	if !isDiscordWebhook(u) {
		return d
	}
	d.Discord = true
	ctx, cancel := context.WithTimeout(context.Background(), alertTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, raw, nil)
	if err != nil {
		return d
	}
	resp, err := a.client.Do(req)
	if err != nil {
		d.Problem = "Couldn't reach Discord to look up its channel; sending a test tries again."
		return d
	}
	defer resp.Body.Close()
	switch {
	case resp.StatusCode == http.StatusNotFound || resp.StatusCode == http.StatusUnauthorized:
		d.Problem = "Discord says this webhook doesn't exist (deleted, or the URL is wrong)."
	case resp.StatusCode/100 == 2:
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
		if name, ch, ok := parseDiscordWebhook(body); ok {
			d.Name, d.ChannelURL = name, ch
		}
	default:
		d.Problem = "Discord didn't say which channel this is; sending a test tries again."
	}
	return d
}

var errAlertBudget = errors.New("too many alerts went out in the last few minutes; try again in a minute")

// test sends content now and says how it went: the webhook's answer,
// never its URL. It counts against the same budget as alerts.
func (a *alerter) test(content string) error {
	if !a.configured() {
		return errors.New("no webhook is configured")
	}
	a.mu.Lock()
	ok := a.take(a.now())
	a.mu.Unlock()
	if !ok {
		return errAlertBudget
	}
	body, _ := json.Marshal(map[string]any{"content": content, "allowed_mentions": map[string]any{"parse": []string{}}})
	_, err := a.postOnce(body)
	return err
}

// alertSource says where the webhook in use came from, for Settings.
func (s *Server) alertSource() (source string, setAt time.Time) {
	u, at, err := s.store.AlertWebhook()
	switch {
	case err == nil && u != "":
		return "settings", at
	case s.cfg.AlertWebhook != "":
		return "env", time.Time{}
	}
	return "", time.Time{}
}
