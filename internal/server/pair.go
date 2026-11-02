package server

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
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
	pairTTL             = 10 * time.Minute
	maxPairings         = 50 // waiting at once, across all clients
	maxPairingsPerIP    = 3  // per exact address
	maxPairingsPerGroup = 8  // per IPv6 /64 (the same as per address for IPv4)
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

// expirePairingsLocked drops old requests, and revokes approved tokens that
// were never collected, so no working token is left that nobody holds. The
// deadline is stored with the token, so this also covers requests lost in a
// restart, and it can't hit a newer token of the same name. Needs s.pairMu.
func (s *Server) expirePairingsLocked() {
	now := s.now()
	for id, p := range s.pairings {
		if !now.Before(p.Expires()) {
			delete(s.pairings, id)
		}
	}
	s.revokeUncollected(now)
}

func (s *Server) revokeUncollected(now time.Time) {
	for _, name := range s.store.RevokeUncollected(now) {
		s.audit.Add(audit.Event{Actor: "keydrop", Action: "token.revoke", Target: name, Detail: "approved pairing never collected"})
	}
	s.sweepRotations(now)
}

// sourceGroup is what the per-group cap counts: the address, or its /64
// for IPv6, since one machine usually has a whole /64 to pick from. A LAN
// usually shares one /64 too, so the group cap is higher than the cap per
// exact address.
func sourceGroup(ip string) string {
	a, err := netip.ParseAddr(ip)
	if err != nil {
		return ip
	}
	a = a.Unmap().WithZone("")
	if a.Is6() {
		p, _ := a.Prefix(64)
		return p.String()
	}
	return a.String()
}

// sourcePrefill is the "Allowed from" suggestion for an address.
func sourcePrefill(ip string) string {
	a, err := netip.ParseAddr(ip)
	if err != nil {
		return ""
	}
	return a.Unmap().WithZone("").String()
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

// makePairingRoomLocked reports whether ip may add a pairing request. Each
// address and /64 has its own cap. When the whole list is full, the oldest
// waiting request from the busiest group makes way, as long as that group
// has more than ip's own: so one noisy neighbour can't keep everyone else
// out, and filling the list takes many addresses. Needs s.pairMu.
func (s *Server) makePairingRoomLocked(ip string) bool {
	group := sourceGroup(ip)
	fromIP, perGroup := 0, map[string]int{}
	for _, p := range s.pairings {
		if p.IP == ip {
			fromIP++
		}
		perGroup[sourceGroup(p.IP)]++
	}
	if fromIP >= maxPairingsPerIP || perGroup[group] >= maxPairingsPerGroup {
		return false
	}
	if len(s.pairings) < maxPairings {
		return true
	}
	var victim *pairing
	for _, p := range s.pairings {
		g := sourceGroup(p.IP)
		if p.approved || perGroup[g] <= perGroup[group]+1 {
			continue
		}
		if victim == nil || perGroup[g] > perGroup[sourceGroup(victim.IP)] ||
			(perGroup[g] == perGroup[sourceGroup(victim.IP)] && p.Created.Before(victim.Created)) {
			victim = p
		}
	}
	if victim == nil {
		return false
	}
	delete(s.pairings, victim.ID)
	return true
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
	if !s.makePairingRoomLocked(ip) {
		s.pairMu.Unlock()
		apiError(w, http.StatusTooManyRequests, "too many pairing requests are waiting from this address; approve or deny them, or wait 10 minutes")
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

	s.noisyEvent(r, "unknown", "pair.request", displayCode(p.Code), "claims host "+p.Host+", user "+p.User)
	out := map[string]any{"code": displayCode(p.Code), "path": "/pair/" + p.ID, "poll": poll, "expires_in": int(pairTTL.Seconds())}
	if s.cfg.PublicURL != "" && !s.cfg.PublicURLGuess {
		out["link"] = strings.TrimRight(s.cfg.PublicURL, "/") + "/pair/" + p.ID
	}
	writeJSON(w, http.StatusCreated, out)
}

// apiPairPoll hands the token over once, and only to the address that asked.
// A poll from another address gets 403, not 404, so an agent whose address
// changed isn't told its request is gone.
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
		if subtle.ConstantTimeCompare([]byte(c.pollHash), []byte(h)) == 1 {
			p = c
		}
	}
	if p == nil {
		s.pairMu.Unlock()
		apiError(w, http.StatusNotFound, "no such pairing request: it expired, was denied, or was already collected")
		return
	}
	if p.IP != ip {
		code, from := displayCode(p.Code), p.IP
		s.pairMu.Unlock()
		s.noisyEvent(r, "unknown", "pair.wrongaddr", code, "asked from "+from)
		apiError(w, http.StatusForbidden, "this pairing request was made from "+from+", not "+ip+"; the token is only handed to the address that asked. Run keydrop pair --new from this address")
		return
	}
	if !p.approved {
		s.pairMu.Unlock()
		writeJSON(w, http.StatusOK, map[string]any{"state": "pending"})
		return
	}
	delete(s.pairings, p.ID)
	if err := s.store.Collected(p.token); err != nil {
		s.pairMu.Unlock()
		apiError(w, http.StatusNotFound, "the approved token was revoked or replaced before it was collected; run keydrop pair again")
		return
	}
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
		"name": {suggestName(p.Host)}, "sources": {sourcePrefill(p.IP)},
	}, "")
}

func (s *Server) renderPair(w http.ResponseWriter, r *http.Request, se *session, status int, p pairing, form url.Values, errMsg string) {
	_, exists := tokenNamed(s.store.ListTokens(), form.Get("name"))
	lifetime := store.DefaultTokenLifetime
	if d, err := strconv.Atoi(form.Get("lifetime")); err == nil && store.CheckLifetime(d) == nil {
		lifetime = d
	}
	s.render(w, r, "pair", status, se, page{
		"Title": "Approve an agent", "P": p, "Code": displayCode(p.Code),
		"Form": form, "Exists": exists, "Error": errMsg, "Namespaces": s.store.Namespaces(),
		"NSOpts": nsOpts(s.store.Namespaces(), splitList(form.Get("namespaces"))), "Lifetime": lifetime,
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
	for _, k := range []string{"name", "permission", "write", "sources", "replace", "lifetime"} {
		form.Set(k, strings.TrimSpace(r.PostFormValue(k)))
	}
	form.Set("namespaces", strings.Join(formNamespaces(r), ","))
	name, nss := form.Get("name"), splitList(form.Get("namespaces"))
	perm, permOK := formPermission(form)
	form.Set("permission", string(perm))
	sources, err := store.ParseSources(form.Get("sources"))
	days, lifeErr := formLifetime(r)
	switch {
	case lifeErr != nil:
		s.renderPair(w, r, se, http.StatusBadRequest, p, form, "New token every: "+lifeErr.Error()+".")
		return
	case !permOK:
		s.renderPair(w, r, se, http.StatusBadRequest, p, form, "Permission: read, add or write.")
		return
	case !store.ValidName(name):
		s.renderPair(w, r, se, http.StatusBadRequest, p, form, "Name: lowercase letters, digits, '.', '_' and '-' only.")
		return
	case len(nss) == 0:
		s.renderPair(w, r, se, http.StatusBadRequest, p, form, "Give it at least one namespace.")
		return
	case err != nil:
		s.renderPair(w, r, se, http.StatusBadRequest, p, form, "Allowed from: "+err.Error()+".")
		return
	case store.CheckToken(name, nss, sources) != nil:
		// Checked before Replace revokes anything.
		s.renderPair(w, r, se, http.StatusBadRequest, p, form, "Namespaces: lowercase letters, digits, '.', '_' and '-' only.")
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
	// The agent gets a fresh window to collect it; after that the token is
	// revoked unused.
	now := s.now()
	tok, err := s.store.CreatePairedToken(name, nss, perm, sources, now.Add(pairTTL), days)
	if err != nil {
		s.renderPair(w, r, se, http.StatusBadRequest, p, form, err.Error())
		return
	}
	cur.approved, cur.tokenName, cur.token, cur.namespace = true, name, tok, nss
	cur.Created = now
	detail := "code " + displayCode(cur.Code) + " from " + cur.IP + ", namespaces " + strings.Join(nss, ",") + ", " + string(perm)
	detail += ", allowed from " + sourcesText(sources) + ", " + lifetimeLabel(days)
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

// formPermission reads the permission field: read, add or write. A form
// with only the older write checkbox still works.
func formPermission(form url.Values) (store.Permission, bool) {
	switch p := store.Permission(form.Get("permission")); {
	case p == "":
		if form.Get("write") == "yes" {
			return store.PermWrite, true
		}
		return store.PermRead, true
	case p.Valid():
		return p, true
	}
	return store.PermRead, false
}

func (s *Server) handleTokenPermission(w http.ResponseWriter, r *http.Request, _ string, se *session) {
	name := r.PathValue("name")
	perm, ok := formPermission(url.Values{"permission": {r.PostFormValue("permission")}})
	if !ok || r.PostFormValue("permission") == "" {
		s.renderTokens(w, r, se, http.StatusBadRequest, "Permission: read, add or write.")
		return
	}
	if err := s.store.SetTokenPermission(name, perm); err != nil {
		s.renderTokens(w, r, se, http.StatusNotFound, "There's no agent called "+name+".")
		return
	}
	s.event(r, "admin", "token.permission", name, string(perm))
	http.Redirect(w, r, "/token/"+url.PathEscape(name)+"?msg=permission", http.StatusSeeOther)
}

func sourcesText(src []string) string {
	if len(src) == 0 {
		return "anywhere"
	}
	return strings.Join(src, ", ")
}

func (s *Server) handleTokenNamespaces(w http.ResponseWriter, r *http.Request, _ string, se *session) {
	name := r.PathValue("name")
	nss := formNamespaces(r)
	if err := s.store.SetTokenNamespaces(name, nss); err != nil {
		msg := "Namespaces: tick at least one; names are lowercase letters, digits, '.', '_' and '-'."
		if errors.Is(err, store.ErrNotFound) {
			msg = "There's no agent called " + name + "."
		}
		s.renderTokens(w, r, se, http.StatusBadRequest, msg)
		return
	}
	s.event(r, "admin", "token.namespaces", name, strings.Join(nss, ","))
	http.Redirect(w, r, "/token/"+url.PathEscape(name)+"?msg=namespaces", http.StatusSeeOther)
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
	http.Redirect(w, r, "/token/"+url.PathEscape(name)+"?msg=sources", http.StatusSeeOther)
}
