package main

import (
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"time"

	"github.com/minituff/keydrop/internal/client"
	"github.com/minituff/keydrop/internal/server"
)

// cmdDoctor checks this machine's keydrop setup, one line per check, and
// says what to do about each problem. It changes nothing: no file is
// written, no renewed token collected, no version stamp left, and it never
// touches a secret (so a canary can't tell). It sends no token to a server
// whose certificate doesn't match the pin. Exit 1 if a check failed.
func cmdDoctor(args []string) error {
	if len(args) > 0 {
		fmt.Fprintln(os.Stderr, "usage: keydrop doctor")
		return exitCode(2)
	}
	if !doctor(os.Stdout) {
		return exitCode(1)
	}
	return nil
}

type report struct {
	w      io.Writer
	failed bool
}

// line prints one check; next, if any, is what to do about it.
func (r *report) line(status, check, detail, next string) {
	fmt.Fprintf(r.w, "%-5s %-11s %s\n", status, check, detail)
	if next != "" {
		// Some come from error messages, which start lower-case.
		fmt.Fprintf(r.w, "      → %s\n", strings.ToUpper(next[:1])+next[1:])
	}
	r.failed = r.failed || status == "FAIL"
}

func (r *report) skip(why string, checks ...string) {
	for _, c := range checks {
		r.line("skip", c, "("+why+")", "")
	}
}

// doctor runs every check, writing to w, and reports whether none failed.
func doctor(w io.Writer) bool {
	r := &report{w: w}
	c := doctorConfig(r)
	switch {
	case c == nil:
		r.skip("needs a configuration", "server", "certificate", "token", "access", "version", "clock")
	case !doctorServer(r, c):
		r.skip("needs a working server", "token", "access", "version", "clock")
	default:
		h, body, ok := doctorToken(r, c)
		if !ok {
			r.skip("needs a working token", "access", "version", "clock")
			break
		}
		doctorAccess(r, body)
		doctorVersion(r, h)
		doctorClock(r, h)
	}
	return !r.failed
}

// pairHint is the command that pairs this machine again with the same URL
// and pin (both public).
func pairHint(c *client.Client) string {
	cmd := "keydrop pair --url " + clean(c.URL, false)
	if c.Pin() != "" {
		cmd += " --pin " + clean(c.Pin(), false)
	}
	return "`" + cmd + "`"
}

func doctorConfig(r *report) *client.Client {
	var env []string
	for _, k := range []string{"KEYDROP_URL", "KEYDROP_TOKEN", "KEYDROP_TOKEN_FILE", "KEYDROP_TLS_PIN"} {
		if os.Getenv(k) != "" {
			env = append(env, k) // the name only, never the value
		}
	}
	dir, dirErr := client.ConfigDir()
	if dirErr != nil && !errors.Is(dirErr, client.ErrNoConfigDir) {
		r.line("FAIL", "config", "the config directory can't be trusted", clean(dirErr.Error(), false))
		return nil
	}
	has := func(name string) bool {
		_, err := os.Stat(filepath.Join(dir, name))
		return dirErr == nil && err == nil
	}
	from := "no config directory"
	if dirErr == nil {
		from = dir
		if fi, err := os.Stat(dir); err != nil || !fi.IsDir() {
			from += " (doesn't exist)"
		} else if runtime.GOOS != "windows" {
			from += " (only you can write it)"
		}
	}
	if len(env) > 0 {
		from += "; from the environment: " + strings.Join(env, ", ")
	}
	if (os.Getenv("KEYDROP_URL") == "" && !has("url")) ||
		(os.Getenv("KEYDROP_TOKEN") == "" && os.Getenv("KEYDROP_TOKEN_FILE") == "" && !has("token")) {
		next := "Pair this machine: `keydrop pair --url URL` (add `--pin sha256:…` for a self-signed server; the admin has both), and the admin approves it."
		if has("pairing") {
			next = "A pairing request was started: run `keydrop pair` to keep waiting for the admin to approve it."
		}
		r.line("FAIL", "config", "not paired: "+from, next)
		return nil
	}
	c, err := client.FromEnv()
	if err != nil {
		r.line("FAIL", "config", from, clean(err.Error(), false))
		return nil
	}
	r.line("ok", "config", from, "")
	return c
}

// doctorServer checks /healthz, which needs no token, and the certificate
// it's served with. It reports whether both are fine.
func doctorServer(r *report, c *client.Client) bool {
	u := clean(c.URL, false)
	_, body, err := c.Inspect("/healthz", false)
	var pm *client.PinMismatchError
	var cv *tls.CertificateVerificationError
	var rh tls.RecordHeaderError
	var dns *net.DNSError
	var ne net.Error
	var ae *client.APIError
	tlsFail := errors.As(err, &pm) || errors.As(err, &cv)
	switch {
	case err == nil && strings.TrimSpace(string(body)) == "ok":
		if plainHTTP(c.URL) {
			r.line("warn", "server", u+" answers, over plain http", "This is "+plainHTTPWarning+".")
		} else {
			r.line("ok", "server", u+" answers", "")
		}
	case tlsFail:
		r.line("ok", "server", u+" accepts connections (nothing more is asked of it until its certificate checks out)", "")
	case err == nil || errors.As(err, &ae):
		status := "200"
		if ae != nil {
			status = fmt.Sprint(ae.Status)
		}
		r.line("FAIL", "server", u+" answers (HTTP "+status+" at /healthz), but not like keydrop", "Check the URL with the admin: the host, port or path is probably wrong (keydrop answers \"ok\" at /healthz). Then pair again with the right one.")
	case errors.As(err, &rh):
		r.line("FAIL", "server", u+" answers in plain http, not https", "Check the URL and port with the admin.")
	case errors.As(err, &dns):
		r.line("FAIL", "server", "can't find the host "+clean(dns.Name, false)+" (DNS)", "Check the host name in the URL, and this machine's network and DNS.")
	case errors.Is(err, syscall.ECONNREFUSED):
		r.line("FAIL", "server", "nothing answers at "+u+" (connection refused)", "Check with the admin that keydrop is running and the URL's port is right.")
	case errors.As(err, &ne) && ne.Timeout():
		r.line("FAIL", "server", "no answer from "+u+" in time", "Check with the admin that keydrop is running, and that a firewall lets this machine reach it.")
	default:
		r.line("FAIL", "server", "can't reach "+u+": "+clean(err.Error(), false), "Check the URL, that keydrop is running, and that this machine can reach it.")
	}

	switch {
	case pm != nil:
		got := "no certificate"
		if pm.Got != "" {
			got = clean(pm.Got, false)
		}
		r.line("FAIL", "certificate", "doesn't match the pin: pinned "+clean(pm.Pin, false)+", the server presented "+got,
			"The admin may have replaced the certificate with `keydrop rotate-tls`, which printed the new pin and how to re-pin each agent (docs/upgrading.md). Ask the admin for the new pin; don't trust the presented one on its own: if the certificate wasn't replaced, someone may be intercepting the connection. Nothing was sent to this server.")
	case cv != nil:
		r.line("FAIL", "certificate", "not trusted: "+clean(cv.Err.Error(), false),
			"If keydrop uses its own self-signed certificate, this machine needs its pin: ask the admin for it and pair with `keydrop pair --url URL --pin sha256:…`. Otherwise check the host name in the URL.")
	case err != nil:
		r.skip("needs the server", "certificate")
	case strings.HasPrefix(strings.ToLower(c.URL), "http://"):
		r.skip("plain http has no certificate", "certificate")
	case c.Pin() != "":
		r.line("ok", "certificate", "pinned ("+clean(c.Pin(), false)+"), and the server's matches", "")
	default:
		r.line("ok", "certificate", "not pinned; trusted by this machine's certificate authorities", "")
	}
	return !r.failed
}

// doctorToken asks whoami, without the client's 401 handling (which would
// collect and save a renewed token).
func doctorToken(r *report, c *client.Client) (http.Header, []byte, bool) {
	h, body, err := c.Inspect("/api/v1/whoami", true)
	if err != nil {
		r.line(tokenProblem(c, err))
		return nil, nil, false
	}
	exp, perr := time.Parse(time.RFC3339, h.Get("X-Keydrop-Token-Expires"))
	now := clockNow()
	if perr != nil || exp.Sub(now) > client.WarnWithin || !now.Before(exp) {
		r.line("ok", "token", "the server accepts it", "")
		return h, body, true
	}
	next := "Run `keydrop renew` to ask the admin for its replacement; once they approve, the next keydrop command saves the new token."
	if st := renewState(c); st != nil && st.State == "pending" {
		next = "Its renewal request is waiting: ask the admin to approve it in keydrop's Inbox, then run `keydrop renew --wait`."
	}
	n := client.DaysLeft(exp, now)
	r.line("warn", "token", fmt.Sprintf("the server accepts it, but it expires in %d day%s", n, plural(n)), next)
	return h, body, true
}

// tokenProblem is the token line for a refused whoami. After a 401 it
// asks the renewal status, which the server still answers for a token in
// its renewal grace window or one replaced but not yet collected.
func tokenProblem(c *client.Client, err error) (status, check, detail, next string) {
	var ae *client.APIError
	if !errors.As(err, &ae) {
		return "FAIL", "token", "no answer: " + clean(err.Error(), false), "The server answered a moment ago: try again, and check the network if it keeps failing."
	}
	switch ae.Status {
	case http.StatusUnauthorized:
		switch st := renewState(c); {
		case st == nil:
		case st.State == "approved" && c.TokenPath == "":
			return "FAIL", "token", "replaced by a renewed token that hasn't been collected", client.ErrRenewedNoFile.Error()
		case st.State == "approved":
			return "warn", "token", "replaced by a renewed token that hasn't been collected yet", "Run `keydrop renew` to collect it and save it over " + clean(c.TokenPath, false) + " (any other keydrop command does that too)."
		case st.Expired && st.ExpiresAt != nil:
			return "FAIL", "token", "expired on " + st.ExpiresAt.UTC().Format("2006-01-02") + " (it can still be renewed)", (&client.ExpiredError{At: *st.ExpiresAt, Pending: st.State == "pending"}).Error()
		}
		return "FAIL", "token", "the server refused it (401)", "The server answers the same for a token that is unknown, revoked, replaced or expired more than 30 days ago, so which one can't be told from here. `keydrop renew` would be refused too: ask the person to pair this machine again with " + pairHint(c) + "."
	case http.StatusForbidden:
		return "FAIL", "token", "refused from this machine's address (403): " + clean(ae.Message, false), "Ask the admin to add this machine's address to the token's allowed sources under Agents, or use keydrop from an allowed machine."
	case http.StatusUpgradeRequired:
		return "FAIL", "token", "the server refuses this CLI as too old (426)", clean(ae.Message, false)
	}
	return "FAIL", "token", fmt.Sprintf("the server answered HTTP %d: %s", ae.Status, clean(ae.Message, false)), "Try again in a minute; if it persists, ask the admin to check the server's log."
}

// renewState is the token's renewal status, or nil if the server refuses it.
func renewState(c *client.Client) *client.RenewState {
	var st client.RenewState
	if _, b, err := c.Inspect("/api/v1/token/renew", true); err != nil || json.Unmarshal(b, &st) != nil {
		return nil
	}
	return &st
}

func doctorAccess(r *report, body []byte) {
	w, err := client.ParseWhoami(body)
	if err != nil {
		r.line("FAIL", "access", "the server's answer to whoami can't be read", "Ask the admin to check the server (and any proxy in front of it).")
		return
	}
	ns := clean(strings.Join(w.Namespaces, ", "), false)
	if ns == "" {
		ns = "none"
	}
	d := fmt.Sprintf("%s: namespaces %s, permission %s", clean(w.Name, false), ns, clean(w.Perm(), false))
	if w.ExpiryKnown {
		d += ", expires " + expiresText(w.ExpiresAt, clockNow())
	}
	if len(w.Namespaces) == 0 {
		r.line("warn", "access", d, "Ask the admin to grant this token a namespace under Agents; until then it can't see or store anything.")
		return
	}
	r.line("ok", "access", d, "")
}

// doctorVersion reuses the notice every command shows (once a day), so it
// says the same thing, by the token's self-upgrade setting.
func doctorVersion(r *report, h http.Header) {
	srv := clean(h.Get("X-Keydrop-Version"), false)
	if srv == "" {
		srv = "unnamed (it doesn't say)"
	}
	d := fmt.Sprintf("this CLI is %s, the server is %s (API level %d; the server's is %s, minimum %s)", clean(client.Version, false), srv,
		server.APILevel, clean(h.Get(server.HdrAPILevel), false), clean(h.Get(server.HdrMinCLI), false))
	if n := client.VersionNotice(h); n != "" {
		r.line("warn", "version", d, clean(n, false))
		return
	}
	r.line("ok", "version", d, "")
}

// doctorClock compares this machine's clock with the server's Date header:
// expiry warnings and certificate checks depend on it.
func doctorClock(r *report, h http.Header) {
	t, err := http.ParseTime(h.Get("Date"))
	if err != nil {
		r.skip("the server sent no Date", "clock")
		return
	}
	skew := time.Since(t).Round(time.Second)
	if skew.Abs() <= 2*time.Minute {
		r.line("ok", "clock", "within 2 minutes of the server's", "")
		return
	}
	way := "ahead of"
	if skew < 0 {
		way = "behind"
	}
	r.line("warn", "clock", fmt.Sprintf("%s %s the server's", skew.Abs(), way), "Set this machine's clock right (turn on time sync, NTP): token expiry and certificate checks depend on it.")
}
