package server

import (
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"testing"
)

func TestAlertFormatAuto(t *testing.T) {
	for raw, want := range map[string]string{
		"https://hooks.slack.com/services/T0/B0/fake-slack-path":    formatSlack,
		"https://HOOKS.slack.com/services/T0/B0/fake":               formatSlack,
		"http://hooks.slack.com/services/T0/B0/fake":                formatDiscord,
		"https://hooks.slack.com.evil.example/services/T0/B0/fake":  formatDiscord,
		"https://hooks.example.com/hooks.slack.com/services/x":      formatDiscord,
		"https://discord.com/api/webhooks/123/abc":                  formatDiscord,
		"https://ntfy.example.com/keydrop-alerts":                   formatDiscord,
		"https://notslack.example.com/?u=https://hooks.slack.com/x": formatDiscord,
	} {
		if got := resolveFormat("", raw); got != want {
			t.Errorf("%s: %s, want %s", raw, got, want)
		}
		if got := resolveFormat(formatAuto, raw); got != want {
			t.Errorf("auto %s: %s, want %s", raw, got, want)
		}
	}
	// An explicit format wins over the URL.
	if resolveFormat(formatText, "https://hooks.slack.com/services/x") != formatText ||
		resolveFormat(formatDiscord, "https://hooks.slack.com/services/x") != formatDiscord {
		t.Fatal("explicit format ignored")
	}
	for _, f := range []string{"", "auto", "discord", "slack", "text"} {
		if CheckAlertFormat(f) != nil {
			t.Errorf("%q refused", f)
		}
	}
	for _, f := range []string{"Slack", "ntfy", "json", "https://hooks.example.com/fake-path"} {
		if err := CheckAlertFormat(f); err == nil || !strings.Contains(err.Error(), "auto, discord, slack or text") || strings.Contains(err.Error(), "fake-path") {
			t.Errorf("%q: %v", f, err)
		}
	}
}

func TestAlertBody(t *testing.T) {
	const msg = "keydrop: canary `lab/BAIT` was read by token `bot` from fe80::1%<!channel>&<@U1> at 2026-01-02T03:04:05Z."
	for _, c := range []struct{ format, body, ctype string }{
		// Byte for byte what every earlier release sent.
		{formatDiscord, `{"allowed_mentions":{"parse":[]},"content":"keydrop: canary ` + "`lab/BAIT`" + ` was read by token ` + "`bot`" + ` from fe80::1%\u003c!channel\u003e\u0026\u003c@U1\u003e at 2026-01-02T03:04:05Z."}`, "application/json"},
		{formatSlack, `{"text":"keydrop: canary ` + "`lab/BAIT`" + ` was read by token ` + "`bot`" + ` from fe80::1%\u0026lt;!channel\u0026gt;\u0026amp;\u0026lt;@U1\u0026gt; at 2026-01-02T03:04:05Z."}`, "application/json"},
		{formatText, "keydrop: canary lab/BAIT was read by token bot from fe80::1%<!channel>&<@U1> at 2026-01-02T03:04:05Z.", "text/plain; charset=utf-8"},
	} {
		body, ctype := alertBody(c.format, msg)
		if string(body) != c.body || ctype != c.ctype {
			t.Errorf("%s:\n got %s (%s)\nwant %s (%s)", c.format, body, ctype, c.body, c.ctype)
		}
	}
}

// fakeTransport answers every request with 204 and records it, so URLs on
// real hosts (hooks.slack.com) can be used without the network.
type fakeTransport struct {
	mu  sync.Mutex
	got []string // host, Content-Type, Title, body
}

func (f *fakeTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	b, _ := io.ReadAll(r.Body)
	f.mu.Lock()
	f.got = append(f.got, r.URL.Host+" | "+r.Header.Get("Content-Type")+" | "+r.Header.Get("Title")+" | "+string(b))
	f.mu.Unlock()
	return &http.Response{StatusCode: http.StatusNoContent, Body: http.NoBody, Header: http.Header{}, Request: r}, nil
}

func (f *fakeTransport) all() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.got...)
}

func fakeAlerter(raw, format string) (*alerter, *fakeTransport) {
	ft := &fakeTransport{}
	a := newAlerter(raw)
	a.format = format
	a.client.Transport = ft
	return a, ft
}

func TestAlertFormatsPosted(t *testing.T) {
	for _, c := range []struct{ raw, format, want string }{
		{"https://discord.com/api/webhooks/1/fake", "", "discord.com | application/json |  | {\"allowed_mentions\":{\"parse\":[]},\"content\":\"keydrop: canary `lab/BAIT` was read.\"}"},
		{"https://hooks.slack.com/services/fake", "auto", "hooks.slack.com | application/json |  | {\"text\":\"keydrop: canary `lab/BAIT` was read.\"}"},
		{"https://ntfy.example.com/fake-topic", "text", "ntfy.example.com | text/plain; charset=utf-8 | keydrop | keydrop: canary lab/BAIT was read."},
		{"https://hooks.example.com/fake", "slack", "hooks.example.com | application/json |  | {\"text\":\"keydrop: canary `lab/BAIT` was read.\"}"},
	} {
		a, ft := fakeAlerter(c.raw, c.format)
		a.send("keydrop: canary `lab/BAIT` was read.")
		a.wg.Wait()
		if err := a.test("keydrop: canary `lab/BAIT` was read."); err != nil {
			t.Fatalf("%s test: %v", c.format, err)
		}
		if got := ft.all(); len(got) != 2 || got[0] != c.want || got[1] != c.want {
			t.Errorf("%s %s:\n got %q\nwant %q", c.raw, c.format, got, c.want)
		}
	}
}

// The body is built when it's posted, so an alert queued before the
// webhook is changed in Settings goes out in the new webhook's format.
func TestAlertFormatFollowsURL(t *testing.T) {
	h := newHarness(t)
	h.setup()
	a, ft := fakeAlerter("https://discord.com/api/webhooks/1/fake", "")
	h.srv.alerts = a
	a.mu.Lock()
	a.enqueue("keydrop: canary `lab/BAIT` was read.") // queued, not yet sent
	a.mu.Unlock()
	if code, _ := h.form("/settings/alert-webhook", url.Values{"webhook": {"https://hooks.slack.com/services/T0/B0/fake-slack-path"}}); code != http.StatusSeeOther {
		t.Fatalf("set: %d", code)
	}
	a.once.Do(func() { go a.run() })
	a.wg.Wait()
	if got := ft.all(); len(got) != 1 || got[0] != "hooks.slack.com | application/json |  | {\"text\":\"keydrop: canary `lab/BAIT` was read.\"}" {
		t.Fatalf("got %q", got)
	}
}

func TestAlertFormatSettings(t *testing.T) {
	h := newHarness(t)
	h.setup()
	a, ft := fakeAlerter("", "")
	h.srv.alerts = a
	_, body := h.form("/settings/alert-webhook", url.Values{"webhook": {"https://hooks.slack.com/services/T0/B0/fake-slack-path"}})
	if !strings.Contains(body, "hooks.slack.com</strong> · sent as: <strong>Slack</strong>") || strings.Contains(body, "fake-slack-path") || strings.Contains(body, "Not Discord or Slack") {
		t.Fatal("Settings with a Slack webhook")
	}
	// Not Discord or Slack, on auto: Discord's body, and a hint for ntfy.
	_, body = h.form("/settings/alert-webhook", url.Values{"webhook": {"https://ntfy.example.com/fake-topic-path"}})
	if !strings.Contains(body, "sent as: <strong>Discord</strong>") || !strings.Contains(body, "Not Discord or Slack, so alerts are sent in Discord's format. For ntfy, set KEYDROP_ALERT_FORMAT=text") || strings.Contains(body, "fake-topic-path") {
		t.Fatal("Settings with another webhook on auto")
	}
	// With KEYDROP_ALERT_FORMAT=text: plain text, no hint, and the test
	// alert goes out as plain text.
	h.srv.cfg.AlertFormat, a.format = formatText, formatText
	code, body := h.form("/settings/alert-test", url.Values{})
	if code != http.StatusSeeOther || !strings.Contains(body, "Test alert delivered") || !strings.Contains(body, "sent as: <strong>plain text</strong>") ||
		strings.Contains(body, "Not Discord or Slack") || strings.Contains(body, "fake-topic-path") {
		t.Fatalf("text test alert: %d %s", code, body)
	}
	if got := ft.all(); len(got) != 1 || !strings.HasPrefix(got[0], "ntfy.example.com | text/plain; charset=utf-8 | keydrop | keydrop: test alert, sent from Settings") {
		t.Fatalf("webhook got %q", got)
	}
}
