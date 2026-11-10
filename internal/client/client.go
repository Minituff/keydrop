// Package client talks to a keydrop server with an agent token.
package client

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/minituff/keydrop/internal/server"
	"github.com/minituff/keydrop/internal/store"
)

// Secret is the metadata the API returns.
type Secret = server.APISecret

// Group is an entry's group.
type Group = server.APIGroup

// Whoami describes the token in use.
type Whoami struct {
	Name       string   `json:"name"`
	Namespaces []string `json:"namespaces"`
	Write      bool     `json:"write"`
	// Permission is read, add or write; empty from a server that predates
	// it (then Write says which).
	Permission string `json:"permission"`
	// ExpiresAt is when the token expires; nil for never. ExpiryKnown is
	// false from a server that predates token expiry.
	ExpiresAt   *time.Time `json:"expires_at"`
	ExpiryKnown bool       `json:"-"`
}

// Perm is the token's permission, from either field.
func (w Whoami) Perm() string {
	switch {
	case w.Permission != "":
		return w.Permission
	case w.Write:
		return "write"
	}
	return "read"
}

// Version is this CLI's build version, set by main. When the server is a
// different build, the client says so (see checkVersion).
var Version string

var (
	warnedVersion bool
	warnTo        io.Writer = os.Stderr
	// noticeEvery is how often a compatible-but-different build is
	// mentioned. Agents run the CLI many times an hour; once a day is
	// enough to get it upgraded without burying their output.
	noticeEvery = 24 * time.Hour
)

// versionShape is what a server's version header may look like. Anything
// else is ignored: the notice prints it in keydrop's own voice, and agents
// read that.
var versionShape = regexp.MustCompile(`^[A-Za-z0-9._+-]{1,64}$`)

// checkVersion compares this CLI with the server from an authenticated
// response's headers. A CLI below the server's minimum level is refused
// by the server itself (426, naming `keydrop upgrade`), so here it's only
// about builds that still work: at most one line a day per server build,
// remembered in the config directory. Unversioned local builds ("dev") are
// skipped. The caller passes only successful answers to requests that
// carried a token, so an error page or an unauthenticated answer (pairing)
// can't put words in the notice.
func checkVersion(h http.Header) {
	srv := h.Get("X-Keydrop-Version")
	if warnedVersion || !versionShape.MatchString(srv) || Version == "" || Version == "dev" || srv == "dev" || srv == Version {
		return
	}
	warnedVersion = true
	// Servers before the setting send no header: they expect `keydrop
	// upgrade` to be used. The setting is part of what's remembered, so
	// turning it on or off shows the (reworded) notice again. Only "off"
	// means off; anything else counts as the default.
	off := h.Get(server.HdrSelfUpgrade) == "off"
	seen := srv
	if off {
		seen += " self-upgrade off"
	}
	stamp := filepath.Join(ConfigDir(), "version-notice")
	if fi, err := os.Stat(stamp); err == nil && time.Since(fi.ModTime()) < noticeEvery {
		if b, _ := os.ReadFile(stamp); strings.TrimSpace(string(b)) == seen {
			return
		}
	}
	older := false
	if lvl, err := strconv.Atoi(h.Get(server.HdrAPILevel)); err == nil && lvl < server.APILevel {
		older = true
	}
	switch {
	case older && off:
		fmt.Fprintf(warnTo, "keydrop: the server (%s) is older than this CLI (%s); commands it doesn't support will fail. Ask the admin to update the server.\n", srv, Version)
	case older:
		fmt.Fprintf(warnTo, "keydrop: the server (%s) is older than this CLI (%s); commands it doesn't support will fail. Ask the admin to update the server, or run `keydrop upgrade` to match it.\n", srv, Version)
	case off:
		fmt.Fprintf(warnTo, "keydrop: the server is %s and this CLI is %s. Nothing breaks (no incompatible changes). Self-upgrade is off for this agent, so don't update the CLI yourself: mention it to the user, who can upgrade it or turn self-upgrade on for this agent under Agents.\n", srv, Version)
	default:
		fmt.Fprintf(warnTo, "keydrop: the server is %s and this CLI is %s. Nothing breaks (no incompatible changes), but run `keydrop upgrade` when convenient to match it: it fetches the server's build, checks it, and keeps the old binary as a .bak.\n", srv, Version)
	}
	// Best effort: without the stamp the line just shows again next run.
	if os.MkdirAll(ConfigDir(), 0o700) == nil {
		os.WriteFile(stamp, []byte(seen+"\n"), 0o600)
	}
}

// Client is a configured API client.
type Client struct {
	URL   string
	Token string
	HTTP  *http.Client
	// Label says which agent is acting when several share one token
	// (KEYDROP_AGENT, e.g. "claude"). It only shows in the audit log.
	Label string

	// TokenPath is the file the token was read from, where a renewed
	// token is saved. Empty when it came from KEYDROP_TOKEN: then a renewed
	// token can't be saved, so it isn't collected.
	TokenPath string
	// NoExpiryWarning turns off the "this token expires in N days" line.
	NoExpiryWarning bool

	pin        string
	who        *Whoami
	recovering bool
	warnedExp  bool
}

// ConfigDir is ~/.config/keydrop (or $XDG_CONFIG_HOME/keydrop).
func ConfigDir() string {
	if d := os.Getenv("XDG_CONFIG_HOME"); d != "" {
		return filepath.Join(d, "keydrop")
	}
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".config", "keydrop")
}

func readConfigFile(name string) string {
	b, err := os.ReadFile(filepath.Join(ConfigDir(), name))
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}

// FromEnv builds a client from KEYDROP_URL, KEYDROP_TOKEN(_FILE) and
// KEYDROP_TLS_PIN, falling back to files written by `keydrop login`.
func FromEnv() (*Client, error) {
	u, err := serverURL()
	if err != nil {
		return nil, err
	}
	tok, tokenPath := os.Getenv("KEYDROP_TOKEN"), ""
	if tok == "" {
		path := os.Getenv("KEYDROP_TOKEN_FILE")
		if path == "" {
			path = filepath.Join(ConfigDir(), "token")
		}
		fi, err := os.Stat(path)
		if err != nil {
			return nil, fmt.Errorf("no token: run `keydrop pair` or set KEYDROP_TOKEN_FILE (%v)", err)
		}
		if TooOpen(fi.Mode()) {
			return nil, fmt.Errorf("%s is readable by other users; run chmod 600 %s", path, path)
		}
		b, err := os.ReadFile(path)
		if err != nil {
			return nil, err
		}
		tok = strings.TrimSpace(string(b))
		tokenPath = path
	}
	c := New(u, tok, serverPin())
	c.TokenPath = tokenPath
	c.Label = os.Getenv("KEYDROP_AGENT")
	return c, nil
}

func serverURL() (string, error) {
	u := os.Getenv("KEYDROP_URL")
	if u == "" {
		u = readConfigFile("url")
	}
	if u == "" {
		return "", errors.New("no server configured: run `keydrop pair --url https://…` or set KEYDROP_URL")
	}
	return u, nil
}

func serverPin() string {
	if pin := os.Getenv("KEYDROP_TLS_PIN"); pin != "" {
		return pin
	}
	return readConfigFile("pin")
}

// AskUpgrade asks the server whether this agent may upgrade its own CLI
// (the admin's self-upgrade setting), from version from. The server logs
// the ask. A server from before the setting (404) has nothing to say
// against it.
func (c *Client) AskUpgrade(from string) (bool, error) {
	warnedVersion = true // no "run keydrop upgrade" notice while upgrading
	var resp struct {
		Allowed bool `json:"allowed"`
	}
	err := c.do("POST", "/api/v1/cli/upgrade", map[string]string{"from": from}, &resp)
	if IsNotFound(err) {
		return true, nil
	}
	return resp.Allowed, err
}

// Download copies a file the server hands out without a token (a CLI build,
// its SHA256SUMS) to w, over the same pinned connection as the API, and
// refuses plain http: what it fetches gets run. At most limit bytes.
func (c *Client) Download(path string, w io.Writer, limit int64) error {
	if !strings.HasPrefix(strings.ToLower(c.URL), "https://") {
		return errors.New("refusing to download over plain http: set the server's https:// URL")
	}
	hc := *c.HTTP
	hc.Timeout = 10 * time.Minute // a build is several megabytes
	resp, err := hc.Get(c.URL + path)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		msg, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return &APIError{Status: resp.StatusCode, Message: serverMessage(string(msg))}
	}
	n, err := io.Copy(w, io.LimitReader(resp.Body, limit+1))
	if err != nil {
		return err
	}
	if n > limit {
		return fmt.Errorf("%s is larger than %d bytes", path, limit)
	}
	if resp.ContentLength >= 0 && n != resp.ContentLength {
		return fmt.Errorf("%s was cut off (%d of %d bytes)", path, n, resp.ContentLength)
	}
	return nil
}

// New builds a client. If pin is set ("sha256:<hex>"), the server's
// certificate must match it exactly instead of chaining to a public CA,
// which is how self-signed servers are trusted.
//
// A pin only means something over https: with an http:// URL every request
// fails (ErrPinNeedsHTTPS) rather than silently going unverified, and a
// redirect away from https is refused.
func New(baseURL, token, pin string) *Client {
	tr := http.DefaultTransport.(*http.Transport).Clone()
	if pin != "" {
		tr.TLSClientConfig = &tls.Config{
			InsecureSkipVerify: true, // replaced by the pin check below
			VerifyPeerCertificate: func(raw [][]byte, _ [][]*x509.Certificate) error {
				if len(raw) == 0 || !strings.EqualFold(server.Fingerprint(raw[0]), pin) {
					return errors.New("server certificate doesn't match KEYDROP_TLS_PIN")
				}
				return nil
			},
		}
	}
	hc := &http.Client{Transport: tr, Timeout: 30 * time.Second}
	hc.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		switch {
		case pin != "" && req.URL.Scheme != "https":
			return ErrPinNeedsHTTPS
		case via[len(via)-1].URL.Scheme == "https" && req.URL.Scheme != "https":
			// The token, or a build about to be run, would go in the clear.
			return ErrRedirectToHTTP
		case len(via) >= 10:
			return errors.New("stopped after 10 redirects")
		}
		return nil
	}
	return &Client{URL: strings.TrimRight(baseURL, "/"), Token: token, HTTP: hc, pin: pin}
}

// ErrPinNeedsHTTPS: a certificate pin is set but the URL is plain http, so
// there's no certificate to check.
var ErrPinNeedsHTTPS = errors.New("a TLS pin is set but the URL isn't https://, so it can't be checked; use the https:// URL")

// ErrRedirectToHTTP: an https server redirected to plain http.
var ErrRedirectToHTTP = errors.New("the server redirected from https to plain http, which keydrop refuses; fix the server's or proxy's redirect")

// APIError is a non-2xx response.
type APIError struct {
	Status  int
	Message string
}

func (e *APIError) Error() string { return fmt.Sprintf("%s (HTTP %d)", e.Message, e.Status) }

// IsNotFound reports whether err is a 404.
func IsNotFound(err error) bool {
	var ae *APIError
	return errors.As(err, &ae) && ae.Status == http.StatusNotFound
}

// do sends one API call. On a 401 it checks whether the token was renewed
// (by the admin, or after `keydrop renew`) and if so collects the new
// token, saves it and repeats the call; otherwise it says whether the
// token expired.
func (c *Client) do(method, path string, body, out any) error {
	var b []byte
	if body != nil {
		var err error
		if b, err = json.Marshal(body); err != nil {
			return err
		}
	}
	err := c.send(method, path, b, out)
	var ae *APIError
	if c.Token == "" || c.recovering || !errors.As(err, &ae) || ae.Status != http.StatusUnauthorized {
		return err
	}
	retry, rerr := c.recover401()
	if rerr != nil {
		return rerr
	}
	if !retry {
		return err
	}
	return c.send(method, path, b, out)
}

func (c *Client) send(method, path string, body []byte, out any) error {
	if c.pin != "" && !strings.HasPrefix(strings.ToLower(c.URL), "https://") {
		return ErrPinNeedsHTTPS
	}
	var rd io.Reader
	if body != nil {
		rd = bytes.NewReader(body)
	}
	req, err := http.NewRequest(method, c.URL+path, rd)
	if err != nil {
		return err
	}
	if c.Token != "" {
		req.Header.Set("Authorization", "Bearer "+c.Token)
	}
	if c.Label != "" {
		req.Header.Set("X-Keydrop-Agent", c.Label)
	}
	req.Header.Set(server.HdrCLILevel, strconv.Itoa(server.APILevel))
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	// Only a successful answer to a request with a token is the keydrop
	// server speaking to this token: an error page may come from a proxy,
	// and pairing is unauthenticated.
	if c.Token != "" && resp.StatusCode >= 200 && resp.StatusCode < 300 {
		checkVersion(resp.Header)
		c.checkExpiry(resp.Header.Get("X-Keydrop-Token-Expires"))
	}
	data, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode >= 300 {
		var e struct{ Error string }
		if json.Unmarshal(data, &e) != nil || e.Error == "" {
			e.Error = string(data)
		}
		return &APIError{Status: resp.StatusCode, Message: serverMessage(e.Error)}
	}
	if out != nil {
		return json.Unmarshal(data, out)
	}
	return nil
}

// Whoami returns the token's name and grants (cached).
func (c *Client) Whoami() (*Whoami, error) {
	if c.who != nil {
		return c.who, nil
	}
	var raw json.RawMessage
	if err := c.do("GET", "/api/v1/whoami", nil, &raw); err != nil {
		return nil, err
	}
	var w Whoami
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(raw, &w); err != nil {
		return nil, err
	}
	if json.Unmarshal(raw, &fields) == nil {
		_, w.ExpiryKnown = fields["expires_at"]
	}
	c.who = &w
	return &w, nil
}

// Resolve turns "name" into "namespace/name" when the token has exactly one
// namespace, and validates "namespace/name" otherwise.
func (c *Client) Resolve(ref string) (ns, name string, err error) {
	if ns, name, ok := strings.Cut(ref, "/"); ok {
		return ns, name, nil
	}
	w, err := c.Whoami()
	if err != nil {
		return "", "", err
	}
	if len(w.Namespaces) != 1 {
		return "", "", fmt.Errorf("%q: this token has several namespaces (%s), so write it as namespace/name", ref, strings.Join(w.Namespaces, ", "))
	}
	return w.Namespaces[0], ref, nil
}

func secretPath(ns, name string) string {
	return "/api/v1/secrets/" + url.PathEscape(ns) + "/" + url.PathEscape(name)
}

// List returns secret metadata. query may set new, pending or namespace.
func (c *Client) List(query url.Values) ([]Secret, error) {
	var out []Secret
	p := "/api/v1/secrets"
	if len(query) > 0 {
		p += "?" + query.Encode()
	}
	return out, c.do("GET", p, nil, &out)
}

// Get returns one secret's metadata.
func (c *Client) Get(ref string) (*Secret, error) {
	ns, name, err := c.Resolve(ref)
	if err != nil {
		return nil, err
	}
	var s Secret
	return &s, c.do("GET", secretPath(ns, name), nil, &s)
}

// TooOpen says whether a file's mode lets other users read it. Windows has
// no such bits: Go reports 0666 for every file there, and what protects a
// file is its ACL, so the check would refuse every token.
func TooOpen(m os.FileMode) bool {
	return !isWindows && m.Perm()&0o077 != 0
}

// Reveal returns a value, and whether it's a variable (which isn't
// masked). purpose is recorded in the audit log for a secret.
func (c *Client) Reveal(ref, purpose string) (value string, variable bool, err error) {
	r, err := c.RevealStatus(ref, purpose)
	return r.Value, r.Kind == "variable", err
}

// Revealed is a value with its kind, and its status when it isn't ok.
type Revealed struct {
	Ref    string        `json:"ref"`
	Value  string        `json:"value"`
	Kind   string        `json:"kind"`
	Status *store.Status `json:"status"`
}

// RevealStatus is Reveal with the key's status, so a caller can warn
// about using a key marked leaked or replaced.
func (c *Client) RevealStatus(ref, purpose string) (Revealed, error) {
	var out Revealed
	ns, name, err := c.Resolve(ref)
	if err != nil {
		return out, err
	}
	p := secretPath(ns, name) + "/reveal"
	if purpose != "" {
		p += "?purpose=" + url.QueryEscape(purpose)
	}
	err = c.do("POST", p, nil, &out)
	return out, err
}

// HistoryEvent is one change in the history.
type HistoryEvent = server.APIEvent

// History lists changes to keys the token can see, newest first. ns and
// name filter when set.
func (c *Client) History(ns, name string, limit int) ([]HistoryEvent, error) {
	q := url.Values{}
	if ns != "" {
		q.Set("namespace", ns)
	}
	if name != "" {
		q.Set("name", name)
	}
	if limit > 0 {
		q.Set("limit", fmt.Sprint(limit))
	}
	var out []HistoryEvent
	return out, c.do("GET", "/api/v1/history?"+q.Encode(), nil, &out)
}

// Flag asks the admin to look at a key. reason and link are seen only by
// the admin.
func (c *Client) Flag(ref, reason, link string) error {
	ns, name, err := c.Resolve(ref)
	if err != nil {
		return err
	}
	return c.do("POST", secretPath(ns, name)+"/flag", map[string]string{"reason": reason, "link": link}, nil)
}

// SetStatus sets a key's status: ok, expired, revoked, leaked, or
// replaced-by with replacedBy.
func (c *Client) SetStatus(ref, status, replacedBy string) error {
	ns, name, err := c.Resolve(ref)
	if err != nil {
		return err
	}
	return c.do("POST", secretPath(ns, name)+"/status", map[string]string{"status": status, "replaced_by": replacedBy}, nil)
}

// Note proposes a note and returns the admin's approval link.
func (c *Client) Note(ref, text string) (string, error) {
	ns, name, err := c.Resolve(ref)
	if err != nil {
		return "", err
	}
	var out struct{ URL string }
	err = c.do("POST", secretPath(ns, name)+"/notes", map[string]string{"text": text}, &out)
	return out.URL, err
}

// PutOptions are the optional fields for Put.
type PutOptions struct {
	Description *string `json:"description,omitempty"`
	Usage       *string `json:"usage,omitempty"`
	Expires     *string `json:"expires,omitempty"`
	Variable    bool    `json:"variable"` // always sent: omitting it would mean "secret" anyway
	Overwrite   bool    `json:"overwrite"`
}

// Put stores a value (write-enabled tokens only).
func (c *Client) Put(ref, value string, o PutOptions) error {
	ns, name, err := c.Resolve(ref)
	if err != nil {
		return err
	}
	body := struct {
		Value string `json:"value"`
		PutOptions
	}{value, o}
	return c.do("PUT", secretPath(ns, name), body, nil)
}

// Request asks the human for a secret and returns the link to fill it in.
func (c *Client) Request(ref, description, usage string) (string, error) {
	ns, name, err := c.Resolve(ref)
	if err != nil {
		return "", err
	}
	var out struct{ URL string }
	err = c.do("POST", "/api/v1/requests", map[string]string{
		"namespace": ns, "name": name, "description": description, "usage": usage,
	}, &out)
	return out.URL, err
}

// Batch is the answer to a batch request.
type Batch struct {
	Refs []string          `json:"refs"`
	ID   string            `json:"batch"`
	URL  string            `json:"url"`  // the batch's card, if the server knows its public URL
	URLs map[string]string `json:"urls"` // each key's page
}

// RequestBatch asks the human for several keys at once, filled on one
// card. They must be in one namespace. group is a group name to propose:
// the human decides whether to use it.
func (c *Client) RequestBatch(refs []string, group, description, usage string) (*Batch, error) {
	var ns string
	var names []string
	for _, ref := range refs {
		n, name, err := c.Resolve(ref)
		if err != nil {
			return nil, err
		}
		if ns != "" && n != ns {
			return nil, fmt.Errorf("one request can't mix namespaces (%s and %s); make one per namespace", ns, n)
		}
		ns = n
		names = append(names, name)
	}
	var out Batch
	err := c.do("POST", "/api/v1/requests/batch", map[string]any{
		"namespace": ns, "names": names, "group": group, "description": description, "usage": usage,
	}, &out)
	if IsNotFound(err) {
		return nil, errors.New("this keydrop server is too old to request several keys at once; request them one at a time, or ask the admin to upgrade it")
	}
	return &out, err
}

// Expiring lists secrets that expire within days (or already have).
func (c *Client) Expiring(days int) ([]Secret, error) {
	var out []Secret
	return out, c.do("GET", fmt.Sprintf("/api/v1/expiring?days=%d", days), nil, &out)
}

// PairStart is the answer to a pairing request.
type PairStart struct {
	Code      string `json:"code"`
	Path      string `json:"path"`
	Link      string `json:"link"` // set when the server knows its public URL
	Poll      string `json:"poll"`
	ExpiresIn int    `json:"expires_in"`
}

// Pair asks the server for a token. It needs no token; the admin approves.
func (c *Client) Pair(host, user string) (*PairStart, error) {
	var p PairStart
	err := c.do("POST", "/api/v1/pair", map[string]string{"host": host, "user": user}, &p)
	return &p, err
}

// PairResult is the state of a pairing request.
type PairResult struct {
	State      string   `json:"state"` // pending or approved
	Token      string   `json:"token"`
	Name       string   `json:"name"`
	Namespaces []string `json:"namespaces"`
}

// PairPoll checks a pairing request; once approved it returns the token,
// exactly once. A 404 means it expired, was denied or was collected.
func (c *Client) PairPoll(poll string) (*PairResult, error) {
	var r PairResult
	err := c.do("POST", "/api/v1/pair/poll", map[string]string{"poll": poll}, &r)
	return &r, err
}
