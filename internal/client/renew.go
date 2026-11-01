package client

import (
	"errors"
	"fmt"
	"math"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/minituff/keydrop/internal/store"
)

// Token renewal, agent side. A token that expires can be renewed: `keydrop
// renew` asks the admin, who approves it in the Inbox (or renews it from
// the Agents page without being asked). Either way the server replaces the
// token, and the agent collects the new one with the old one and saves it
// over the token file. Nothing is renewed without the admin.

// now is the clock; only the e2e tests' build (tag e2eclock) changes it.
var now = time.Now

// SetClock replaces the clock, for the e2e tests' build.
func SetClock(f func() time.Time) { now = f }

// warnWithin is how close to expiry every command starts warning.
const warnWithin = 14 * 24 * time.Hour

// RenewState is where a token's renewal stands.
type RenewState struct {
	Name      string     `json:"name"`
	State     string     `json:"state"` // none, pending, approved, never
	ExpiresAt *time.Time `json:"expires_at"`
	Expired   bool       `json:"expired"` // by the server's clock
	Created   bool       `json:"created"`
	CollectBy *time.Time `json:"collect_by"`
}

// DaysLeft is how many days until t, rounded up: a token made for 90 days
// expires "in 90 days", not 89.
func DaysLeft(t, now time.Time) int {
	return int(math.Ceil(t.Sub(now).Hours() / 24))
}

func dayText(n int) string {
	if n == 1 {
		return "1 day"
	}
	return fmt.Sprintf("%d days", n)
}

// checkExpiry warns once per run when the token expires soon. h is the
// X-Keydrop-Token-Expires header: RFC 3339, "never", or absent.
func (c *Client) checkExpiry(h string) {
	if c.NoExpiryWarning || c.warnedExp || h == "" || h == "never" {
		return
	}
	t, err := time.Parse(time.RFC3339, h)
	if err != nil {
		return
	}
	at := now()
	if t.Sub(at) > warnWithin || !at.Before(t) {
		return
	}
	c.warnedExp = true
	fmt.Fprintf(warnTo, "keydrop: this token expires in %s. Run `keydrop renew` to ask the admin to extend it.\n", dayText(DaysLeft(t, at)))
}

// ExpiredError: the token expired. Renewal can still be asked for during
// the grace window.
type ExpiredError struct {
	At      time.Time
	Pending bool // a renewal request is already waiting
}

func (e *ExpiredError) Error() string {
	d := e.At.UTC().Format("2006-01-02")
	if e.Pending {
		return "this token expired on " + d + ". Its renewal request is waiting: ask the admin to approve it in keydrop's Inbox, then run `keydrop renew --wait`."
	}
	return "this token expired on " + d + ". Run `keydrop renew`, then ask the admin to approve it in keydrop's Inbox."
}

// ErrRenewedNoFile: the token was renewed, but it came from KEYDROP_TOKEN,
// so there's no file to save the new one in. Collecting it anyway would
// lose it the moment this process exits.
var ErrRenewedNoFile = errors.New("this token was renewed, but it comes from KEYDROP_TOKEN, so the new one can't be saved: unset KEYDROP_TOKEN (or set KEYDROP_TOKEN_FILE) and run `keydrop renew --wait`")

// raw runs one call without the 401 handling.
func (c *Client) raw(method, path string, out any) error {
	was := c.recovering
	c.recovering = true
	defer func() { c.recovering = was }()
	return c.do(method, path, nil, out)
}

// recover401 runs after a 401. It reports whether the call should be
// repeated (a renewed token was collected, or another process sharing the
// token file already did), or returns a clearer error than "invalid token".
func (c *Client) recover401() (bool, error) {
	// Another process may have collected already: the file has moved on.
	if c.TokenPath != "" {
		if cur := readToken(c.TokenPath); cur != "" && cur != c.Token {
			c.useToken(cur)
			return true, nil
		}
	}
	st, err := c.RenewStatus()
	if err != nil {
		return false, nil // not renewable (unknown, revoked, past the grace window): the 401 stands
	}
	switch {
	case st.State == "approved":
		if _, err := c.Collect(); err != nil {
			return false, err
		}
		return true, nil
	case st.Expired && st.ExpiresAt != nil:
		return false, &ExpiredError{At: *st.ExpiresAt, Pending: st.State == "pending"}
	}
	return false, nil
}

func (c *Client) useToken(tok string) {
	c.Token, c.who = tok, nil
}

// RenewStatus says where the token's renewal stands. It works for an
// expired token during the grace window, and for a renewed one until the
// new token is collected.
func (c *Client) RenewStatus() (*RenewState, error) {
	var st RenewState
	return &st, c.raw("GET", "/api/v1/token/renew", &st)
}

// Renew asks the admin to renew this token. Asking again while a request
// is waiting changes nothing.
func (c *Client) Renew() (*RenewState, error) {
	var st RenewState
	return &st, c.raw("POST", "/api/v1/token/renew", &st)
}

// Collect fetches the token that replaced this one and saves it over the
// token file (atomically, mode 600; url and pin untouched). It returns
// the path written, or "" when another process sharing the file had
// already done it. The token itself is never printed.
func (c *Client) Collect() (string, error) {
	if c.TokenPath == "" {
		return "", ErrRenewedNoFile
	}
	unlock, err := lockFile(c.TokenPath + ".lock")
	if err != nil {
		return "", fmt.Errorf("locking the token file: %w", err)
	}
	defer unlock()
	// Re-read under the lock: whoever held it before may have collected.
	if cur := readToken(c.TokenPath); cur != "" && cur != c.Token {
		c.useToken(cur)
		return "", nil
	}
	var res struct {
		Token string `json:"token"`
	}
	if err := c.raw("POST", "/api/v1/token/collect", &res); err != nil {
		var ae *APIError
		if errors.As(err, &ae) && (ae.Status == http.StatusUnauthorized || ae.Status == http.StatusNotFound) {
			if cur := readToken(c.TokenPath); cur != "" && cur != c.Token {
				c.useToken(cur)
				return "", nil
			}
		}
		return "", fmt.Errorf("collecting the renewed token: %w", err)
	}
	if !strings.HasPrefix(res.Token, store.TokenPrefix) {
		return "", errors.New("collecting the renewed token: the server's answer has no token")
	}
	if err := writeFileAtomic(c.TokenPath, []byte(res.Token+"\n")); err != nil {
		return "", fmt.Errorf("saving the renewed token (the old one still collects it until the new one is used): %w", err)
	}
	c.useToken(res.Token)
	fmt.Fprintf(warnTo, "keydrop: token renewed; new token saved to %s\n", c.TokenPath)
	return c.TokenPath, nil
}

func readToken(path string) string {
	b, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}

// writeFileAtomic replaces path with data: a temp file in the same
// directory, mode 600, synced, renamed over it, then the directory synced.
// A reader sees the old file or the new one, never half of either.
func writeFileAtomic(path string, data []byte) error {
	dir := filepath.Dir(path)
	f, err := os.CreateTemp(dir, ".token-*")
	if err != nil {
		return err
	}
	tmp := f.Name()
	ok := false
	defer func() {
		if !ok {
			f.Close()
			os.Remove(tmp)
		}
	}()
	if err := f.Chmod(0o600); err != nil && !isWindows {
		return err
	}
	if _, err := f.Write(data); err != nil {
		return err
	}
	if err := f.Sync(); err != nil {
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		return err
	}
	ok = true
	syncDir(dir)
	return nil
}
