package server

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/minituff/keydrop/internal/audit"
	"github.com/minituff/keydrop/internal/store"
)

// Pairing replaces pasting a token: the agent asks to pair, the admin
// approves the request in the UI (setting name, namespaces and allowed
// sources), and the agent collects its token. Requests live in memory only
// and expire quickly, so a restart just means pairing again.
const (
	pairTTL          = 10 * time.Minute
	maxPairings      = 10 // waiting at once, across all clients
	maxPairingsPerIP = 3
)

type pairing struct {
	ID       string // in the admin's approval link
	Code     string // shown to both sides, to check the link matches the agent
	IP       string // where the request came from; the token is only handed back there
	Host     string // claimed by the machine, unverified
	User     string // claimed by the machine, unverified
	Created  time.Time
	pollHash string // the agent's collection secret, hashed

	approved  bool
	tokenName string
	token     string // plaintext, held until the agent collects it
	namespace []string
}

func (p *pairing) Expires() time.Time { return p.Created.Add(pairTTL) }

func hashPoll(poll string) string {
	h := sha256.Sum256([]byte(poll))
	return hex.EncodeToString(h[:])
}

// expirePairingsLocked drops old requests. An approved token that was never
// collected is revoked, so no working token is left that nobody holds.
// Needs s.pairMu.
func (s *Server) expirePairingsLocked() {
	now := s.now()
	for id, p := range s.pairings {
		if now.Before(p.Expires()) {
			continue
		}
		delete(s.pairings, id)
		if p.approved {
			if s.store.RevokeToken(p.tokenName) == nil {
				s.audit.Add(audit.Event{Actor: "keydrop", Action: "token.revoke", Target: p.tokenName, Detail: "approved pairing never collected"})
			}
		}
	}
}

// pendingPairings lists requests waiting for the admin, oldest first.
func (s *Server) pendingPairings() []pairing {
	s.pairMu.Lock()
	defer s.pairMu.Unlock()
	s.expirePairingsLocked()
	var out []pairing
	for _, p := range s.pairings {
		if !p.approved {
			out = append(out, *p)
		}
	}
	for i := 1; i < len(out); i++ {
		for j := i; j > 0 && out[j].Created.Before(out[j-1].Created); j-- {
			out[j], out[j-1] = out[j-1], out[j]
		}
	}
	return out
}

// cleanClaim keeps a machine-supplied name safe to show and log.
func cleanClaim(s string) string {
	var b strings.Builder
	for _, c := range s {
		if b.Len() >= 64 {
			break
		}
		if c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || strings.ContainsRune("._-@", c) {
			b.WriteRune(c)
		}
	}
	if b.Len() == 0 {
		return "unknown"
	}
	return b.String()
}

// suggestName turns a claimed hostname into a valid token name.
func suggestName(host string) string {
	var b strings.Builder
	for _, c := range strings.ToLower(host) {
		if c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-' || c == '_' || c == '.' {
			b.WriteRune(c)
		}
	}
	name := strings.TrimLeft(b.String(), "._-")
	if len(name) > 64 {
		name = name[:64]
	}
	if !store.ValidName(name) || name == "unknown" {
		return ""
	}
	return name
}

// apiPairStart is unauthenticated: anyone who can reach keydrop may ask to
// pair, and only the admin can approve. The caps keep a noisy client from
// filling the list.
func (s *Server) apiPairStart(w http.ResponseWriter, r *http.Request) {
	var b struct{ Host, User string }
	if err := json.NewDecoder(r.Body).Decode(&b); err != nil {
		apiError(w, http.StatusBadRequest, "body must be JSON: "+err.Error())
		return
	}
	ip := s.clientIP(r)
	s.pairMu.Lock()
	s.expirePairingsLocked()
	fromIP := 0
	for _, p := range s.pairings {
		if p.IP == ip {
			fromIP++
		}
	}
	if len(s.pairings) >= maxPairings || fromIP >= maxPairingsPerIP {
		s.pairMu.Unlock()
		apiError(w, http.StatusTooManyRequests, "too many pairing requests are waiting; approve or deny them, or wait 10 minutes")
		return
	}
	poll := randomString(32)
	p := &pairing{
		ID: randomString(16), Code: newSetupCode(), IP: ip,
		Host: cleanClaim(b.Host), User: cleanClaim(b.User),
		Created: s.now(), pollHash: hashPoll(poll),
	}
	s.pairings[p.ID] = p
	s.pairMu.Unlock()

	s.event(r, "unknown", "pair.request", displayCode(p.Code), "claims host "+p.Host+", user "+p.User)
	out := map[string]any{"code": displayCode(p.Code), "path": "/pair/" + p.ID, "poll": poll, "expires_in": int(pairTTL.Seconds())}
	if s.cfg.PublicURL != "" && !s.cfg.PublicURLGuess {
		out["link"] = strings.TrimRight(s.cfg.PublicURL, "/") + "/pair/" + p.ID
	}
	writeJSON(w, http.StatusCreated, out)
}

// apiPairPoll hands the token over once, and only to the address that asked.
func (s *Server) apiPairPoll(w http.ResponseWriter, r *http.Request) {
	var b struct{ Poll string }
	if err := json.NewDecoder(r.Body).Decode(&b); err != nil || b.Poll == "" {
		apiError(w, http.StatusBadRequest, "body must be JSON with poll")
		return
	}
	h, ip := hashPoll(b.Poll), s.clientIP(r)
	s.pairMu.Lock()
	s.expirePairingsLocked()
	var p *pairing
	for _, c := range s.pairings {
		if subtle.ConstantTimeCompare([]byte(c.pollHash), []byte(h)) == 1 && c.IP == ip {
			p = c
		}
	}
	if p == nil {
		s.pairMu.Unlock()
		apiError(w, http.StatusNotFound, "no such pairing request: it expired, was denied, or was already collected")
		return
	}
	if !p.approved {
		s.pairMu.Unlock()
		writeJSON(w, http.StatusOK, map[string]any{"state": "pending"})
		return
	}
	delete(s.pairings, p.ID)
	s.pairMu.Unlock()
	s.event(r, "token:"+p.tokenName, "pair.collect", p.tokenName, "")
	writeJSON(w, http.StatusOK, map[string]any{"state": "approved", "token": p.token, "name": p.tokenName, "namespaces": p.namespace})
}

// ---- admin side ----

func (s *Server) getPairing(id string) (pairing, bool) {
	s.pairMu.Lock()
	defer s.pairMu.Unlock()
	s.expirePairingsLocked()
	p, ok := s.pairings[id]
	if !ok || p.approved {
		return pairing{}, false
	}
	return *p, true
}

func (s *Server) pairGone(w http.ResponseWriter, r *http.Request) {
	s.message(w, r, http.StatusNotFound, "Pairing request not found",
		"It expired (requests last 10 minutes), or it was already approved or denied. Ask the agent to run keydrop pair again.")
}

func (s *Server) handlePair(w http.ResponseWriter, r *http.Request, _ string, se *session) {
	p, ok := s.getPairing(r.PathValue("id"))
	if !ok {
		s.pairGone(w, r)
		return
	}
	s.renderPair(w, r, se, http.StatusOK, p, url.Values{
		"name": {suggestName(p.Host)}, "sources": {p.IP},
	}, "")
}

func (s *Server) renderPair(w http.ResponseWriter, r *http.Request, se *session, status int, p pairing, form url.Values, errMsg string) {
	_, exists := tokenNamed(s.store.ListTokens(), form.Get("name"))
	s.render(w, r, "pair", status, se, page{
		"Title": "Approve an agent", "P": p, "Code": displayCode(p.Code),
		"Form": form, "Exists": exists, "Error": errMsg, "Namespaces": s.store.Namespaces(),
	})
}

func tokenNamed(ts []store.Token, name string) (store.Token, bool) {
	for _, t := range ts {
		if t.Name == name {
			return t, true
		}
	}
	return store.Token{}, false
}

func (s *Server) handlePairApprove(w http.ResponseWriter, r *http.Request, _ string, se *session) {
	id := r.PathValue("id")
	p, ok := s.getPairing(id)
	if !ok {
		s.pairGone(w, r)
		return
	}
	form := url.Values{}
	for _, k := range []string{"name", "namespaces", "write", "sources", "replace"} {
		form.Set(k, strings.TrimSpace(r.PostFormValue(k)))
	}
	name, nss, write := form.Get("name"), splitList(form.Get("namespaces")), form.Get("write") == "yes"
	sources, err := store.ParseSources(form.Get("sources"))
	switch {
	case !store.ValidName(name):
		s.renderPair(w, r, se, http.StatusBadRequest, p, form, "Name: lowercase letters, digits, '.', '_' and '-' only.")
		return
	case len(nss) == 0:
		s.renderPair(w, r, se, http.StatusBadRequest, p, form, "Give it at least one namespace.")
		return
	case err != nil:
		s.renderPair(w, r, se, http.StatusBadRequest, p, form, "Allowed from: "+err.Error()+".")
		return
	}

	s.pairMu.Lock()
	defer s.pairMu.Unlock()
	cur, ok := s.pairings[id]
	if !ok || cur.approved { // expired or handled in another tab meanwhile
		s.pairGone(w, r)
		return
	}
	if _, exists := tokenNamed(s.store.ListTokens(), name); exists {
		if form.Get("replace") != "yes" {
			s.renderPair(w, r, se, http.StatusConflict, p, form, "An agent called "+name+" already exists. Tick \"Replace it\" to revoke its old token, or pick another name.")
			return
		}
		if err := s.store.RevokeToken(name); err == nil {
			s.event(r, "admin", "token.revoke", name, "replaced by pairing")
		}
	}
	tok, err := s.store.CreateToken(name, nss, write, sources)
	if err != nil {
		s.renderPair(w, r, se, http.StatusBadRequest, p, form, err.Error())
		return
	}
	// The agent gets a fresh window to collect it; after that the token is
	// revoked unused.
	cur.approved, cur.tokenName, cur.token, cur.namespace = true, name, tok, nss
	cur.Created = s.now()
	detail := "code " + displayCode(cur.Code) + " from " + cur.IP + ", namespaces " + strings.Join(nss, ",")
	if write {
		detail += ", write"
	}
	detail += ", allowed from " + sourcesText(sources)
	s.event(r, "admin", "pair.approve", name, detail)
	http.Redirect(w, r, "/tokens?msg=paired", http.StatusSeeOther)
}

func (s *Server) handlePairDeny(w http.ResponseWriter, r *http.Request, _ string, se *session) {
	id := r.PathValue("id")
	s.pairMu.Lock()
	p, ok := s.pairings[id]
	if ok && !p.approved {
		delete(s.pairings, id)
	}
	s.pairMu.Unlock()
	if !ok || p.approved {
		s.pairGone(w, r)
		return
	}
	s.event(r, "admin", "pair.deny", displayCode(p.Code), "from "+p.IP)
	http.Redirect(w, r, "/tokens?msg=denied", http.StatusSeeOther)
}

func sourcesText(src []string) string {
	if len(src) == 0 {
		return "anywhere"
	}
	return strings.Join(src, ", ")
}

func (s *Server) handleTokenSources(w http.ResponseWriter, r *http.Request, _ string, se *session) {
	name := r.PathValue("name")
	sources, err := store.ParseSources(r.PostFormValue("sources"))
	if err == nil {
		err = s.store.SetTokenSources(name, sources)
	}
	if err != nil {
		msg := "Allowed from: " + err.Error() + "."
		if errors.Is(err, store.ErrNotFound) {
			msg = "There's no agent called " + name + "."
		}
		s.renderTokens(w, r, se, http.StatusBadRequest, msg)
		return
	}
	s.event(r, "admin", "token.sources", name, sourcesText(sources))
	http.Redirect(w, r, "/tokens?msg=sources", http.StatusSeeOther)
}
