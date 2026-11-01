// Package server is keydrop's HTTP side: the admin UI and the
// agent API.
package server

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"sync"
	"time"

	"github.com/minituff/keydrop/internal/audit"
	"github.com/minituff/keydrop/internal/auth"
	"github.com/minituff/keydrop/internal/store"
)

// Config is everything the server needs that isn't in the store.
type Config struct {
	// PublicURL is the base URL people use in a browser, for links in
	// request replies and the log, e.g. https://secrets.example.com.
	PublicURL string
	// PublicURLGuess means PublicURL wasn't configured. Pairing links then
	// use the URL the agent connected to instead.
	PublicURLGuess bool
	// CookieSecure marks the session cookie Secure. Leave it on unless the UI
	// is reached over plain HTTP.
	CookieSecure bool
	// TrustedProxies are the reverse proxies allowed to set X-Forwarded-For.
	TrustedProxies []netip.Prefix
	// ResetAdmin forces setup mode even if an admin exists.
	ResetAdmin bool
	// Version is the server's build version. Agents get it in the
	// X-Keydrop-Version header so the CLI can warn about a mismatch.
	Version string
	// CLI are the CLI builds the server hands out (LoadCLI).
	CLI []CLIBuild
	// CertPin and KeyPin identify keydrop's own self-signed certificate:
	// the CLI pins the certificate, curl pins the key. Empty otherwise.
	CertPin, KeyPin string
	// DirectURL reaches keydrop itself rather than through a proxy, for the
	// pinned install command, e.g. https://10.0.0.5:8443.
	DirectURL string
}

const (
	sessionIdle     = time.Hour
	sessionAbsolute = 8 * time.Hour
	maxBody         = 128 << 10
)

type session struct {
	csrf    string
	created time.Time
	seen    time.Time
	// newTOTP is the seed shown while turning the authenticator on, kept
	// until the first code from it is confirmed.
	newTOTP []byte
}

// Server implements http.Handler.
type Server struct {
	cfg          Config
	store        *store.Store
	audit        *audit.Log
	limiter      *auth.Limiter
	setupLimiter *auth.Limiter
	mux          *http.ServeMux
	now          func() time.Time
	deviceKey    []byte // signs device cookies (see deviceID)

	mu       sync.Mutex
	sessions map[string]*session

	setupMu   sync.Mutex
	setupCode string // empty when setup isn't open
	setupSeed []byte

	pairMu   sync.Mutex
	pairings map[string]*pairing // by ID

	noisyMu sync.Mutex
	noisy   noisyEvents

	// annotations rate-limits flags, statuses and notes per token.
	annotations *rateLimit
	// writes rate-limits puts and requests per token.
	writes *rateLimit
}

// noisyEvents throttles the audit events an unauthenticated client can
// cause, so a host on the network can't fill the disk with them.
type noisyEvents struct {
	byKey        map[string]*noisyKey // address group + action
	window       time.Time            // start of the current global minute
	count        int                  // recorded in this minute
	suppressedGl int                  // left out by the global cap
}

type noisyKey struct {
	last       time.Time
	suppressed int
}

// annotationsPerHour is how many flags, statuses and notes one token may
// send an hour.
const annotationsPerHour = 60

// writesPerHour is how many puts and requests (together) one token may
// send an hour: plenty for provisioning, too few to churn the history.
const writesPerHour = 200

const (
	noisyPerKey    = time.Minute // one recorded event per address and action
	noisyPerMinute = 60          // and at most this many overall
)

// New builds a Server. If no admin exists yet (or ResetAdmin is set) it
// opens setup and logs a one-time setup code.
func New(cfg Config, st *store.Store, al *audit.Log) *Server {
	s := &Server{
		cfg: cfg, store: st, audit: al,
		limiter: auth.NewLimiter(), setupLimiter: auth.NewLimiter(),
		mux: http.NewServeMux(), now: time.Now, sessions: map[string]*session{},
		pairings: map[string]*pairing{}, deviceKey: st.DeriveKey("device cookie"),
		annotations: newRateLimit(annotationsPerHour, time.Hour),
		writes:      newRateLimit(writesPerHour, time.Hour),
	}
	if !st.AdminConfigured() || cfg.ResetAdmin {
		s.setupCode = newSetupCode()
		s.setupSeed = auth.NewTOTPSecret()
		base := strings.TrimRight(cfg.PublicURL, "/")
		log.Printf("admin setup is open. Go to %s/setup and enter the setup code %s", base, displayCode(s.setupCode))
		log.Printf("or open %s/setup?code=%s", base, s.setupCode)
		log.Printf("(the code works once, and only proves you can read this log; a restart before setup makes a new one)")
	}
	s.revokeUncollected(time.Now()) // paired tokens orphaned by a restart
	s.routes()
	return s
}

// Setup codes avoid 0/O and 1/I, which are easy to mistype from a log.
const setupAlphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"

// newSetupCode returns 6 characters (30 bits). It only has to stop someone
// else on the network claiming an empty install, and guesses are
// rate-limited, so it's short enough to type from a phone.
func newSetupCode() string {
	b := make([]byte, 6)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	for i := range b {
		b[i] = setupAlphabet[b[i]&31] // 32 symbols, so no modulo bias
	}
	return string(b)
}

// displayCode splits a code as ABC-DEF for reading.
func displayCode(c string) string { return c[:3] + "-" + c[3:] }

// normalizeCode accepts lower case, spaces and dashes.
func normalizeCode(c string) string {
	return strings.NewReplacer("-", "", " ", "").Replace(strings.ToUpper(strings.TrimSpace(c)))
}

func randomString(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

func (s *Server) routes() {
	m := s.mux
	m.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("ok\n")) })
	m.HandleFunc("GET /static/style.css", s.handleCSS)
	m.HandleFunc("GET /install.sh", s.handleInstallScript)
	m.HandleFunc("GET /cli/{file}", s.handleCLI)
	m.HandleFunc("GET /setup.md", s.handleSetupGuide)

	m.HandleFunc("GET /setup", s.handleSetupForm)
	m.HandleFunc("POST /setup", s.handleSetup)
	m.HandleFunc("GET /login", s.handleLoginForm)
	m.HandleFunc("POST /login", s.handleLogin)
	m.HandleFunc("POST /logout", s.admin(s.handleLogout))

	m.HandleFunc("GET /{$}", s.admin(s.handleDashboard))
	m.HandleFunc("GET /new", s.admin(s.handleNew))
	m.HandleFunc("GET /inbox", s.admin(s.handleInbox))
	m.HandleFunc("POST /secrets", s.admin(s.handleCreateSecret))
	m.HandleFunc("GET /secret/{ns}/{name}", s.admin(s.handleSecret))
	m.HandleFunc("POST /secret/{ns}/{name}/value", s.admin(s.handleSetValue))
	m.HandleFunc("POST /secret/{ns}/{name}/meta", s.admin(s.handleSetMeta))
	m.HandleFunc("POST /secret/{ns}/{name}/rollback", s.admin(s.handleRollback))
	m.HandleFunc("POST /secret/{ns}/{name}/delete", s.admin(s.handleDelete))
	m.HandleFunc("POST /secret/{ns}/{name}/status", s.admin(s.handleSetStatus))
	m.HandleFunc("POST /secret/{ns}/{name}/flags/{id}/resolve", s.admin(s.handleResolveFlag))
	m.HandleFunc("POST /secret/{ns}/{name}/notes/{id}/approve", s.admin(s.handleApproveNote))
	m.HandleFunc("POST /secret/{ns}/{name}/notes/{id}/remove", s.admin(s.handleRemoveNote))
	m.HandleFunc("POST /secret/{ns}/{name}/proposal/approve", s.admin(s.handleApproveProposal))
	m.HandleFunc("POST /secret/{ns}/{name}/proposal/reject", s.admin(s.handleRejectProposal))
	m.HandleFunc("GET /tokens", s.admin(s.handleTokens))
	m.HandleFunc("GET /tokens/setup", s.admin(s.handleAgentSetup))
	m.HandleFunc("POST /tokens", s.admin(s.handleCreateToken))
	m.HandleFunc("POST /tokens/{name}/revoke", s.admin(s.handleRevokeToken))
	m.HandleFunc("POST /tokens/{name}/sources", s.admin(s.handleTokenSources))
	m.HandleFunc("POST /tokens/{name}/permission", s.admin(s.handleTokenPermission))
	m.HandleFunc("GET /pair/{id}", s.admin(s.handlePair))
	m.HandleFunc("POST /pair/{id}/approve", s.admin(s.handlePairApprove))
	m.HandleFunc("POST /pair/{id}/deny", s.admin(s.handlePairDeny))
	m.HandleFunc("POST /secret/{ns}/{name}/reveal", s.admin(s.handleReveal))
	m.HandleFunc("GET /audit", s.admin(s.handleAudit))
	m.HandleFunc("GET /settings", s.admin(s.handleSettings))
	m.HandleFunc("POST /settings/totp/start", s.admin(s.handleTOTPStart))
	m.HandleFunc("POST /settings/totp/on", s.admin(s.handleTOTPOn))
	m.HandleFunc("POST /settings/totp/off", s.admin(s.handleTOTPOff))
	m.HandleFunc("POST /settings/password", s.admin(s.handlePassword))
	m.HandleFunc("POST /settings/autogroups", s.admin(s.handleAutoGroups))
	m.HandleFunc("GET /groups", s.admin(s.handleGroups))
	m.HandleFunc("POST /groups", s.admin(s.handleCreateGroup))
	m.HandleFunc("POST /groups/promote", s.admin(s.handlePromoteGroup))
	m.HandleFunc("POST /groups/{ns}/{slug}", s.admin(s.handleUpdateGroup))
	m.HandleFunc("POST /groups/{ns}/{slug}/delete", s.admin(s.handleDeleteGroup))
	m.HandleFunc("POST /secret/{ns}/{name}/group", s.admin(s.handleSetEntryGroup))
	m.HandleFunc("POST /requests/fill", s.admin(s.handleFillRequests))

	m.HandleFunc("POST /api/v1/pair", s.apiPairStart) // no token yet: the admin approves
	m.HandleFunc("POST /api/v1/pair/poll", s.apiPairPoll)
	m.HandleFunc("GET /api/v1/whoami", s.agent(s.apiWhoami))
	m.HandleFunc("GET /api/v1/secrets", s.agent(s.apiList))
	m.HandleFunc("GET /api/v1/secrets/{ns}/{name}", s.agent(s.apiGet))
	m.HandleFunc("PUT /api/v1/secrets/{ns}/{name}", s.agent(s.apiPut))
	m.HandleFunc("POST /api/v1/secrets/{ns}/{name}/reveal", s.agent(s.apiReveal))
	m.HandleFunc("POST /api/v1/secrets/{ns}/{name}/ack", s.agent(s.apiAck))
	m.HandleFunc("POST /api/v1/requests", s.agent(s.apiRequest))
	m.HandleFunc("POST /api/v1/requests/batch", s.agent(s.apiRequestBatch))
	m.HandleFunc("GET /api/v1/expiring", s.agent(s.apiExpiring))
	m.HandleFunc("GET /api/v1/history", s.agent(s.apiHistory))
	m.HandleFunc("POST /api/v1/secrets/{ns}/{name}/flag", s.agent(s.apiFlag))
	m.HandleFunc("POST /api/v1/secrets/{ns}/{name}/status", s.agent(s.apiStatus))
	m.HandleFunc("POST /api/v1/secrets/{ns}/{name}/notes", s.agent(s.apiNote))
}

// ServeHTTP adds security headers and a body limit to every response.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	h := w.Header()
	h.Set("Content-Security-Policy", "default-src 'none'; style-src 'self'; img-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'")
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("X-Frame-Options", "DENY")
	h.Set("Referrer-Policy", "no-referrer")
	h.Set("Cache-Control", "no-store")
	h.Set("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
	if s.cfg.CookieSecure {
		h.Set("Strict-Transport-Security", "max-age=31536000")
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxBody)
	s.mux.ServeHTTP(w, r)
}

// clientIP is the remote address, or the first untrusted hop in
// X-Forwarded-For when the request came through a trusted proxy. Every
// X-Forwarded-For line counts: a proxy that adds its own line rather than
// appending to the client's must not let the client's line decide.
// noisyEvent records an event that an unauthenticated request can cause
// (a bad token, a pairing request, a failed login): at most one a minute
// per address (IPv6: per /64) and action, and 60 a minute overall. What's
// left out is counted, and the next recorded event says how many.
func (s *Server) noisyEvent(r *http.Request, actor, action, target, detail string) {
	ip := s.clientIP(r)
	now := s.now()
	key := sourceGroup(ip) + " " + action
	s.noisyMu.Lock()
	n := &s.noisy
	if n.byKey == nil {
		n.byKey = map[string]*noisyKey{}
	}
	if now.Sub(n.window) >= time.Minute {
		n.window, n.count = now, 0
	}
	k := n.byKey[key]
	if k != nil && now.Sub(k.last) < noisyPerKey {
		k.suppressed++
		s.noisyMu.Unlock()
		return
	}
	if n.count >= noisyPerMinute {
		n.suppressedGl++
		s.noisyMu.Unlock()
		return
	}
	if len(n.byKey) > 10000 {
		for kk, v := range n.byKey {
			if now.Sub(v.last) >= noisyPerKey && v.suppressed == 0 {
				delete(n.byKey, kk)
			}
		}
	}
	if k == nil {
		k = &noisyKey{}
		n.byKey[key] = k
	}
	extra := ""
	if k.suppressed > 0 {
		extra = fmt.Sprintf("+%d more like this from this address not logged", k.suppressed)
	}
	if n.suppressedGl > 0 {
		if extra != "" {
			extra += "; "
		}
		extra += fmt.Sprintf("+%d other unauthenticated events not logged (rate limit)", n.suppressedGl)
	}
	k.last, k.suppressed = now, 0
	n.count++
	n.suppressedGl = 0
	s.noisyMu.Unlock()
	if extra != "" {
		if detail != "" {
			detail = extra + "; " + detail // first, so clipping keeps it
		} else {
			detail = extra
		}
	}
	s.audit.Add(audit.Event{Actor: actor, Action: action, Target: target, Detail: detail, IP: s.clientIP(r), Unauthenticated: true})
}

func (s *Server) clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	addr, err := netip.ParseAddr(host)
	if err != nil || !s.trusted(addr) {
		return host
	}
	hops := strings.Split(strings.Join(r.Header.Values("X-Forwarded-For"), ","), ",")
	for i := len(hops) - 1; i >= 0; i-- {
		hop := strings.TrimSpace(hops[i])
		a, err := netip.ParseAddr(hop)
		if err != nil {
			break
		}
		if !s.trusted(a) {
			return hop
		}
	}
	return host
}

func (s *Server) trusted(a netip.Addr) bool {
	for _, p := range s.cfg.TrustedProxies {
		if p.Contains(a.Unmap()) {
			return true
		}
	}
	return false
}

// ---- sessions ----

func (s *Server) cookieName() string {
	if s.cfg.CookieSecure {
		return "__Host-keydrop" // browser enforces Secure, Path=/ and no Domain
	}
	return "keydrop"
}

func (s *Server) newSession(w http.ResponseWriter) {
	id := randomString(32)
	now := s.now()
	s.mu.Lock()
	s.sessions[id] = &session{csrf: randomString(24), created: now, seen: now}
	s.mu.Unlock()
	http.SetCookie(w, &http.Cookie{
		Name: s.cookieName(), Value: id, Path: "/", HttpOnly: true,
		Secure: s.cfg.CookieSecure, SameSite: http.SameSiteStrictMode,
		MaxAge: int(sessionAbsolute / time.Second),
	})
}

func (s *Server) currentSession(r *http.Request) (string, *session) {
	c, err := r.Cookie(s.cookieName())
	if err != nil {
		return "", nil
	}
	now := s.now()
	s.mu.Lock()
	defer s.mu.Unlock()
	for id, se := range s.sessions { // drop expired sessions as we go
		if now.Sub(se.seen) > sessionIdle || now.Sub(se.created) > sessionAbsolute {
			delete(s.sessions, id)
		}
	}
	se, ok := s.sessions[c.Value]
	if !ok {
		return "", nil
	}
	se.seen = now
	return c.Value, se
}

func (s *Server) endSession(w http.ResponseWriter, id string) {
	s.mu.Lock()
	delete(s.sessions, id)
	s.mu.Unlock()
	http.SetCookie(w, &http.Cookie{Name: s.cookieName(), Value: "", Path: "/", MaxAge: -1, HttpOnly: true, Secure: s.cfg.CookieSecure, SameSite: http.SameSiteStrictMode})
}

// ---- device cookies ----

// A device cookie marks a browser that has logged in before. It grants
// nothing: it only lets that browser keep trying to log in while someone
// else on the network has used up the global failed-login limit. It's
// signed with a key derived from the master key, so it survives restarts.
const deviceTTL = 365 * 24 * time.Hour

func (s *Server) deviceCookieName() string {
	if s.cfg.CookieSecure {
		return "__Host-keydrop-device"
	}
	return "keydrop-device"
}

func (s *Server) deviceMAC(b []byte) []byte {
	m := hmac.New(sha256.New, s.deviceKey)
	m.Write(b)
	return m.Sum(nil)
}

// deviceID returns the ID in a valid, unexpired device cookie, or "".
func (s *Server) deviceID(r *http.Request) string {
	c, err := r.Cookie(s.deviceCookieName())
	if err != nil {
		return ""
	}
	raw, err := base64.RawURLEncoding.DecodeString(c.Value)
	if err != nil || len(raw) != 16+8+32 || !hmac.Equal(s.deviceMAC(raw[:24]), raw[24:]) {
		return ""
	}
	if s.now().Unix() > int64(binary.BigEndian.Uint64(raw[16:24])) {
		return ""
	}
	return base64.RawURLEncoding.EncodeToString(raw[:16])
}

// setDeviceCookie marks this browser as one that has logged in.
func (s *Server) setDeviceCookie(w http.ResponseWriter) {
	raw := make([]byte, 24, 56)
	if _, err := rand.Read(raw[:16]); err != nil {
		panic(err)
	}
	binary.BigEndian.PutUint64(raw[16:], uint64(s.now().Add(deviceTTL).Unix()))
	raw = append(raw, s.deviceMAC(raw)...)
	http.SetCookie(w, &http.Cookie{
		Name: s.deviceCookieName(), Value: base64.RawURLEncoding.EncodeToString(raw), Path: "/",
		HttpOnly: true, Secure: s.cfg.CookieSecure, SameSite: http.SameSiteStrictMode,
		MaxAge: int(deviceTTL / time.Second),
	})
}

// tryLogin reserves a password attempt. A browser that has logged in
// before is counted on its own and exempt from the global limit, so others
// failing can't lock it out; anyone else is counted by address.
func (s *Server) tryLogin(r *http.Request) (*auth.Attempt, error) {
	if dev := s.deviceID(r); dev != "" {
		return s.limiter.Try("device:"+dev, true, s.now())
	}
	return s.limiter.Try("ip:"+s.clientIP(r), false, s.now())
}

type adminHandler func(w http.ResponseWriter, r *http.Request, sid string, se *session)

// admin requires a logged-in session, and on POST a matching CSRF token and
// no cross-site fetch.
func (s *Server) admin(h adminHandler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		sid, se := s.currentSession(r)
		if se == nil {
			if s.setupOpen() {
				http.Redirect(w, r, "/setup", http.StatusSeeOther)
				return
			}
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}
		if r.Method == http.MethodPost {
			if site := r.Header.Get("Sec-Fetch-Site"); site != "" && site != "same-origin" && site != "none" {
				http.Error(w, "cross-site request refused", http.StatusForbidden)
				return
			}
			if subtle.ConstantTimeCompare([]byte(r.PostFormValue("csrf")), []byte(se.csrf)) != 1 {
				http.Error(w, "form expired, go back and reload the page", http.StatusForbidden)
				return
			}
		}
		h(w, r, sid, se)
	}
}

func (s *Server) setupOpen() bool {
	s.setupMu.Lock()
	defer s.setupMu.Unlock()
	return s.setupCode != ""
}
