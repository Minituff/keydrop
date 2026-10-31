// Package server is keydrop's HTTP side: the write-only admin UI and the
// agent API.
package server

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"log"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"sync"
	"time"

	"github.com/minituff/keydrop/internal/audit"
	"github.com/minituff/keydrop/internal/auth"
	"github.com/minituff/keydrop/internal/notify"
	"github.com/minituff/keydrop/internal/store"
)

// Config is everything the server needs that isn't in the store.
type Config struct {
	// PublicURL is the base URL people use in a browser, for links in
	// webhooks and request replies, e.g. https://secrets.example.com.
	PublicURL string
	// CookieSecure marks the session cookie Secure. Leave it on unless the UI
	// is reached over plain HTTP.
	CookieSecure bool
	// TrustedProxies are the reverse proxies allowed to set X-Forwarded-For.
	TrustedProxies []netip.Prefix
	// ResetAdmin forces setup mode even if an admin exists.
	ResetAdmin bool
	Notifier   *notify.Notifier
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
}

// Server implements http.Handler.
type Server struct {
	cfg     Config
	store   *store.Store
	audit   *audit.Log
	limiter *auth.Limiter
	mux     *http.ServeMux
	now     func() time.Time

	mu       sync.Mutex
	sessions map[string]*session

	setupMu    sync.Mutex
	setupToken string // empty when setup isn't open
	setupSeed  []byte
}

// New builds a Server. If no admin exists yet (or ResetAdmin is set) it
// opens setup and logs a one-time setup link.
func New(cfg Config, st *store.Store, al *audit.Log) *Server {
	s := &Server{
		cfg: cfg, store: st, audit: al, limiter: auth.NewLimiter(),
		mux: http.NewServeMux(), now: time.Now, sessions: map[string]*session{},
	}
	if !st.AdminConfigured() || cfg.ResetAdmin {
		s.setupToken = randomString(24)
		s.setupSeed = auth.NewTOTPSecret()
		log.Printf("admin setup is open. Visit %s/setup?token=%s", strings.TrimRight(cfg.PublicURL, "/"), s.setupToken)
		log.Printf("(the setup link works once and is printed only here, in the container log)")
	}
	s.routes()
	return s
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

	m.HandleFunc("GET /setup", s.handleSetupForm)
	m.HandleFunc("POST /setup", s.handleSetup)
	m.HandleFunc("GET /login", s.handleLoginForm)
	m.HandleFunc("POST /login", s.handleLogin)
	m.HandleFunc("POST /logout", s.admin(s.handleLogout))

	m.HandleFunc("GET /{$}", s.admin(s.handleDashboard))
	m.HandleFunc("POST /secrets", s.admin(s.handleCreateSecret))
	m.HandleFunc("GET /secret/{ns}/{name}", s.admin(s.handleSecret))
	m.HandleFunc("POST /secret/{ns}/{name}/value", s.admin(s.handleSetValue))
	m.HandleFunc("POST /secret/{ns}/{name}/meta", s.admin(s.handleSetMeta))
	m.HandleFunc("POST /secret/{ns}/{name}/rollback", s.admin(s.handleRollback))
	m.HandleFunc("POST /secret/{ns}/{name}/delete", s.admin(s.handleDelete))
	m.HandleFunc("GET /tokens", s.admin(s.handleTokens))
	m.HandleFunc("POST /tokens", s.admin(s.handleCreateToken))
	m.HandleFunc("POST /tokens/{name}/revoke", s.admin(s.handleRevokeToken))
	m.HandleFunc("GET /audit", s.admin(s.handleAudit))

	m.HandleFunc("GET /api/v1/whoami", s.agent(s.apiWhoami))
	m.HandleFunc("GET /api/v1/secrets", s.agent(s.apiList))
	m.HandleFunc("GET /api/v1/secrets/{ns}/{name}", s.agent(s.apiGet))
	m.HandleFunc("PUT /api/v1/secrets/{ns}/{name}", s.agent(s.apiPut))
	m.HandleFunc("POST /api/v1/secrets/{ns}/{name}/reveal", s.agent(s.apiReveal))
	m.HandleFunc("POST /api/v1/secrets/{ns}/{name}/ack", s.agent(s.apiAck))
	m.HandleFunc("POST /api/v1/requests", s.agent(s.apiRequest))
	m.HandleFunc("GET /api/v1/expiring", s.agent(s.apiExpiring))
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
// X-Forwarded-For when the request came through a trusted proxy.
func (s *Server) clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	addr, err := netip.ParseAddr(host)
	if err != nil || !s.trusted(addr) {
		return host
	}
	hops := strings.Split(r.Header.Get("X-Forwarded-For"), ",")
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

type adminHandler func(w http.ResponseWriter, r *http.Request, sid string, se *session)

// admin requires a logged-in session, and on POST a matching CSRF token and
// no cross-site fetch.
func (s *Server) admin(h adminHandler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		sid, se := s.currentSession(r)
		if se == nil {
			if s.setupOpen() {
				http.Error(w, "keydrop needs setting up: use the setup link from the container log", http.StatusServiceUnavailable)
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
	return s.setupToken != ""
}
