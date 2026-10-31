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
	"strings"
	"time"

	"github.com/minituff/keydrop/internal/server"
)

// Secret is the metadata the API returns.
type Secret = server.APISecret

// Whoami describes the token in use.
type Whoami struct {
	Name       string   `json:"name"`
	Namespaces []string `json:"namespaces"`
	Write      bool     `json:"write"`
}

// Client is a configured API client.
type Client struct {
	URL   string
	Token string
	HTTP  *http.Client
	// Label says which agent is acting when several share one token
	// (KEYDROP_AGENT, e.g. "claude"). It only shows in the audit log.
	Label string

	who *Whoami
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
	u := os.Getenv("KEYDROP_URL")
	if u == "" {
		u = readConfigFile("url")
	}
	if u == "" {
		return nil, errors.New("no server configured: run `keydrop pair --url https://…` or set KEYDROP_URL")
	}
	tok := os.Getenv("KEYDROP_TOKEN")
	if tok == "" {
		path := os.Getenv("KEYDROP_TOKEN_FILE")
		if path == "" {
			path = filepath.Join(ConfigDir(), "token")
		}
		fi, err := os.Stat(path)
		if err != nil {
			return nil, fmt.Errorf("no token: run `keydrop pair` or set KEYDROP_TOKEN_FILE (%v)", err)
		}
		if fi.Mode().Perm()&0o077 != 0 {
			return nil, fmt.Errorf("%s is readable by other users; run chmod 600 %s", path, path)
		}
		b, err := os.ReadFile(path)
		if err != nil {
			return nil, err
		}
		tok = strings.TrimSpace(string(b))
	}
	pin := os.Getenv("KEYDROP_TLS_PIN")
	if pin == "" {
		pin = readConfigFile("pin")
	}
	c := New(u, tok, pin)
	c.Label = os.Getenv("KEYDROP_AGENT")
	return c, nil
}

// New builds a client. If pin is set ("sha256:<hex>"), the server's
// certificate must match it exactly instead of chaining to a public CA,
// which is how self-signed servers are trusted.
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
	return &Client{URL: strings.TrimRight(baseURL, "/"), Token: token, HTTP: &http.Client{Transport: tr, Timeout: 30 * time.Second}}
}

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

func (c *Client) do(method, path string, body, out any) error {
	var rd io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return err
		}
		rd = bytes.NewReader(b)
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
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode >= 300 {
		var e struct{ Error string }
		if json.Unmarshal(data, &e) != nil || e.Error == "" {
			e.Error = strings.TrimSpace(string(data))
		}
		return &APIError{Status: resp.StatusCode, Message: e.Error}
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
	var w Whoami
	if err := c.do("GET", "/api/v1/whoami", nil, &w); err != nil {
		return nil, err
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

// Reveal returns a value, and whether it's a variable (which isn't
// masked). purpose is recorded in the audit log for a secret.
func (c *Client) Reveal(ref, purpose string) (value string, variable bool, err error) {
	ns, name, err := c.Resolve(ref)
	if err != nil {
		return "", false, err
	}
	var out struct{ Value, Kind string }
	p := secretPath(ns, name) + "/reveal"
	if purpose != "" {
		p += "?purpose=" + url.QueryEscape(purpose)
	}
	err = c.do("POST", p, nil, &out)
	return out.Value, out.Kind == "variable", err
}

// Ack clears a secret's "new" flag.
func (c *Client) Ack(ref string) error {
	ns, name, err := c.Resolve(ref)
	if err != nil {
		return err
	}
	return c.do("POST", secretPath(ns, name)+"/ack", nil, nil)
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
