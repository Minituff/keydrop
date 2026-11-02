package server

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"embed"
	"encoding/hex"
	"errors"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/minituff/keydrop/internal/audit"
	"github.com/minituff/keydrop/internal/auth"
	"github.com/minituff/keydrop/internal/qr"
	"github.com/minituff/keydrop/internal/store"
)

//go:embed web
var webFS embed.FS

type expiryInfo struct{ Text, Class string }

var funcs = template.FuncMap{
	"join":          strings.Join,
	"cssv":          func() string { return cssVersion },
	"nsOpts":        nsOpts,
	"newNS":         func() string { return newNamespace },
	"statuses":      func() []string { return []string{"expired", "revoked", "leaked", "replaced-by"} },
	"code":          displayCode,
	"lifetimes":     func() []int { return store.TokenLifetimes },
	"lifetimeLabel": lifetimeLabel,
	"colorPick": func(palette []string, selected string) map[string]any {
		return map[string]any{"Palette": palette, "Selected": selected}
	},
	"fmtTime": func(t time.Time) string {
		if t.IsZero() {
			return "—"
		}
		return t.Local().Format("2006-01-02 15:04")
	},
	"date": func(t *time.Time) string {
		if t == nil {
			return ""
		}
		return t.UTC().Format("2006-01-02")
	},
	"since": func(t *time.Time) string {
		if t == nil {
			return "never"
		}
		return humanAgo(time.Since(*t))
	},
	"expiry": func(t *time.Time) *expiryInfo {
		if t == nil {
			return nil
		}
		days := int(time.Until(*t).Hours() / 24)
		switch {
		case time.Now().After(*t):
			return &expiryInfo{"expired " + t.UTC().Format("2006-01-02"), "expired"}
		case days <= 14:
			return &expiryInfo{fmt.Sprintf("expires in %dd", days), "soon"}
		default:
			return &expiryInfo{"expires " + t.UTC().Format("2006-01-02"), ""}
		}
	},
}

func humanAgo(d time.Duration) string {
	switch {
	case d < time.Minute:
		return "just now"
	case d < time.Hour:
		return fmt.Sprintf("%dm ago", int(d.Minutes()))
	case d < 48*time.Hour:
		return fmt.Sprintf("%dh ago", int(d.Hours()))
	default:
		return fmt.Sprintf("%dd ago", int(d.Hours()/24))
	}
}

var pages = map[string]*template.Template{}

func init() {
	for _, p := range []string{"setup", "login", "dashboard", "secret", "tokens", "token_created", "token", "token_new", "audit", "message", "settings", "pair", "agent_setup", "groups", "new", "inbox"} {
		pages[p] = template.Must(template.New("").Funcs(funcs).ParseFS(webFS, "web/layout.html", "web/"+p+".html"))
	}
}

// Fixed flash messages, picked by key so a link can't inject arbitrary text.
var flashes = map[string]string{
	"saved":          "Saved.",
	"details":        "Details saved.",
	"rolledback":     "Rolled back to the previous value.",
	"deleted":        "Deleted.",
	"revoked":        "Token revoked.",
	"theme":          "Appearance saved for this browser.",
	"paired":         "Approved. The agent collects its token within a few seconds.",
	"denied":         "Pairing request denied.",
	"sources":        "Allowed sources saved.",
	"permission":     "Permission saved.",
	"status":         "Status saved.",
	"resolved":       "Flag resolved.",
	"approved":       "Approved.",
	"rejected":       "Removed.",
	"totpon":         "Authenticator turned on. Logging in now needs a code.",
	"totpoff":        "Authenticator turned off. Logging in now needs only your password.",
	"password":       "Password changed. Any other logged-in browsers were logged out.",
	"grouped":        "Group saved.",
	"groupsaved":     "Group saved.",
	"groupdel":       "Group deleted. Its entries are ungrouped; none was deleted.",
	"autogroups":     "Auto groups setting saved.",
	"renewed":        "Approved. The agent picks up its new token the next time it runs keydrop; the old token now only works for that.",
	"declined":       "Declined. The agent keeps its current token until it runs out.",
	"canary":         "Canary setting saved.",
	"newns":          "Saved in a new namespace. No agent can read it yet: tick the namespace for an agent on the Agents page.",
	"namespaces":     "Namespaces saved.",
	"dismissed":      "Canary alert dismissed. The audit log keeps the read.",
	"canarysettings": "Canary setting saved.",
	"alerttest":      "Test alert delivered: the webhook accepted it. Look for it in the channel below.",
	"webhookset":     "Webhook saved. Send a test alert to check it.",
	"webhookremoved": "Webhook removed.",
}

type page map[string]any

func (s *Server) render(w http.ResponseWriter, r *http.Request, name string, status int, se *session, data page) {
	if data == nil {
		data = page{}
	}
	if se != nil {
		data["CSRF"] = se.csrf
		if _, ok := data["Nav"]; !ok {
			data["Nav"] = navFor(r.URL.Path)
		}
		n, _ := s.inboxCounts()
		data["InboxCount"] = n
		data["Dups"] = s.takeDups(se)
		data["Refresh"] = s.sessionRefresh(r, se)
	}
	data["Theme"] = s.theme(r)
	if f, ok := flashes[r.URL.Query().Get("msg")]; ok {
		data["Flash"] = f
	} else if f := filledFlash(r); f != "" {
		data["Flash"] = f
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	if err := pages[name].ExecuteTemplate(w, "layout", data); err != nil {
		log.Printf("render %s: %v", name, err)
	}
}

// sessionRefresh is the meta refresh for a logged-in page: a few seconds
// after its session would time out, the page reloads by itself, so an
// expired session lands on the login page instead of looking logged in
// until the next click. No JavaScript: the browser does it. If another tab
// kept the session alive, the reload just shows the page again. A server
// restart ends every session too; a page can't see that without polling.
func (s *Server) sessionRefresh(r *http.Request, se *session) string {
	s.mu.Lock()
	end := se.seen.Add(sessionIdle)
	if abs := se.created.Add(sessionAbsolute); abs.Before(end) {
		end = abs
	}
	s.mu.Unlock()
	secs := int(end.Sub(s.now())/time.Second) + 5
	if secs < 5 {
		secs = 5
	}
	// Reload the same page if it was a plain GET of a simple path; anything
	// else (a page shown after a POST, a query) goes to the start page.
	url := "/"
	if r.Method == http.MethodGet && safeRefreshPath.MatchString(r.URL.Path) {
		url = r.URL.Path
	}
	return fmt.Sprintf("%d;url=%s", secs, url)
}

var safeRefreshPath = regexp.MustCompile(`^/[A-Za-z0-9/_.\-]*$`)

func (s *Server) message(w http.ResponseWriter, r *http.Request, status int, title, msg string) {
	s.render(w, r, "message", status, nil, page{"Title": title, "Message": msg})
}

// cssVersion changes whenever style.css does. Pages link to
// /static/style.css?v=<it>, so a browser that cached the old file (phones
// hold on to it through a reload) fetches the new one after an upgrade.
var cssVersion = func() string {
	b, _ := webFS.ReadFile("web/style.css")
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:6])
}()

func (s *Server) handleCSS(w http.ResponseWriter, r *http.Request) {
	b, _ := webFS.ReadFile("web/style.css")
	w.Header().Set("Content-Type", "text/css; charset=utf-8")
	if r.URL.Query().Get("v") == cssVersion {
		w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
	} else {
		w.Header().Set("Cache-Control", "no-cache")
	}
	w.Write(b)
}

func (s *Server) event(r *http.Request, actor, action, target, detail string) {
	s.audit.Add(audit.Event{Actor: actor, Action: action, Target: target, Detail: detail, IP: s.clientIP(r)})
}

func (s *Server) secretURL(ns, name string) string {
	if s.cfg.PublicURL == "" {
		return ""
	}
	return strings.TrimRight(s.cfg.PublicURL, "/") + "/secret/" + url.PathEscape(ns) + "/" + url.PathEscape(name)
}

func crossSite(r *http.Request) bool {
	site := r.Header.Get("Sec-Fetch-Site")
	return site != "" && site != "same-origin" && site != "none"
}

// ---- setup and login ----

// otpView is what a page needs to show a new authenticator seed: a QR code
// (for setting up from a computer), an otpauth link (tapping it on a phone
// opens the authenticator app) and the key for typing in by hand.
func (s *Server) otpView(seed []byte) page {
	account := "admin"
	if u, err := url.Parse(s.cfg.PublicURL); err == nil && u.Hostname() != "" {
		account = u.Hostname() // tells two installs apart in the app
	}
	uri := auth.TOTPURI(seed, "keydrop", account)
	p := page{
		"OTPSecret": auth.TOTPBase32(seed),
		// Built from fixed parts and a base32 seed, so it's safe to mark as a
		// URL (html/template would otherwise blank the otpauth: scheme).
		"OTPURI": template.URL(uri),
	}
	if c, err := qr.Encode(uri); err == nil {
		p["QR"] = template.HTML(c.SVG()) // only numbers and fixed markup
	}
	return p
}

// checkSetupCode compares a setup code, rate-limiting wrong guesses. The
// limit is global as well as per client, since the code is short; a
// restart clears it (and makes a new code), and whoever is setting up can
// read the log, so they can restart.
func (s *Server) checkSetupCode(r *http.Request, code string) (ok, locked bool) {
	att, err := s.setupLimiter.Try(s.clientIP(r), false, s.now())
	if err != nil {
		return false, true
	}
	s.setupMu.Lock()
	want := s.setupCode
	s.setupMu.Unlock()
	ok = want != "" && subtle.ConstantTimeCompare([]byte(normalizeCode(code)), []byte(want)) == 1
	if ok {
		att.Succeed()
	}
	return ok, false
}

func (s *Server) renderSetupCode(w http.ResponseWriter, r *http.Request, locked bool) {
	if locked {
		s.render(w, r, "setup", http.StatusTooManyRequests, nil, page{"Title": "Set up", "Step": "code",
			"Error": "Too many wrong codes. Wait 15 minutes, or restart keydrop: that clears the limit and prints a new code."})
		return
	}
	s.render(w, r, "setup", http.StatusForbidden, nil, page{"Title": "Set up", "Step": "code",
		"Error": "That code doesn't match. Check keydrop's log: the code changes every time keydrop restarts."})
}

func (s *Server) handleSetupForm(w http.ResponseWriter, r *http.Request) {
	if !s.setupOpen() {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	code := r.URL.Query().Get("code")
	if code == "" {
		s.render(w, r, "setup", http.StatusOK, nil, page{"Title": "Set up", "Step": "code"})
		return
	}
	if ok, locked := s.checkSetupCode(r, code); !ok {
		s.renderSetupCode(w, r, locked)
		return
	}
	s.renderSetup(w, r, normalizeCode(code), "totp", "")
}

func (s *Server) renderSetup(w http.ResponseWriter, r *http.Request, code, mfa, errMsg string) {
	status := http.StatusOK
	if errMsg != "" {
		status = http.StatusBadRequest
	}
	s.setupMu.Lock()
	seed := s.setupSeed
	s.setupMu.Unlock()
	data := s.otpView(seed)
	data["Title"], data["Step"], data["Code"], data["MFA"], data["Error"] = "Set up", "account", code, mfa, errMsg
	s.render(w, r, "setup", status, nil, data)
}

func (s *Server) handleSetup(w http.ResponseWriter, r *http.Request) {
	if crossSite(r) {
		http.Error(w, "cross-site request refused", http.StatusForbidden)
		return
	}
	code := r.PostFormValue("code")
	if ok, locked := s.checkSetupCode(r, code); !ok {
		s.renderSetupCode(w, r, locked)
		return
	}
	code = normalizeCode(code)
	mfa := r.PostFormValue("mfa")
	pw, pw2 := r.PostFormValue("password"), r.PostFormValue("password2")
	switch {
	case len([]rune(pw)) < auth.MinPasswordLength:
		s.renderSetup(w, r, code, mfa, fmt.Sprintf("The password needs at least %d characters.", auth.MinPasswordLength))
		return
	case pw != pw2:
		s.renderSetup(w, r, code, mfa, "The passwords don't match.")
		return
	}
	s.setupMu.Lock()
	seed := s.setupSeed
	s.setupMu.Unlock()
	var step int64
	if mfa == "none" {
		seed = nil
	} else {
		var ok bool
		if step, ok = auth.CheckTOTP(seed, r.PostFormValue("totp"), s.now()); !ok {
			s.renderSetup(w, r, code, mfa, "That authenticator code didn't match. Check the keydrop entry in the app and try again, or choose password only.")
			return
		}
	}
	hash, err := auth.HashPassword(pw)
	if err == nil {
		err = s.store.SetAdmin(hash, seed)
	}
	if err == nil && seed != nil {
		err = s.store.UseTOTPStep(step)
	}
	if err != nil {
		log.Printf("setup: %v", err)
		s.renderSetup(w, r, code, mfa, "Couldn't save the admin login. Check keydrop's log.")
		return
	}
	s.setupMu.Lock()
	s.setupCode, s.setupSeed = "", nil
	s.setupMu.Unlock()
	s.mu.Lock()
	s.sessions = map[string]*session{} // a reset logs everyone out
	s.mu.Unlock()
	detail := "with authenticator"
	if seed == nil {
		detail = "password only"
	}
	s.event(r, "admin", "admin.setup", "", detail)
	s.setDeviceCookie(w)
	s.newSession(w)
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func (s *Server) renderLogin(w http.ResponseWriter, r *http.Request, status int, errMsg string) {
	s.render(w, r, "login", status, nil, page{"Title": "Log in", "TOTP": s.store.TOTPEnabled(), "Error": errMsg})
}

func (s *Server) handleLoginForm(w http.ResponseWriter, r *http.Request) {
	if !s.store.AdminConfigured() {
		http.Redirect(w, r, "/setup", http.StatusSeeOther)
		return
	}
	s.renderLogin(w, r, http.StatusOK, "")
}

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	now := s.now()
	if crossSite(r) {
		http.Error(w, "cross-site request refused", http.StatusForbidden)
		return
	}
	att, err := s.tryLogin(r)
	if err != nil {
		s.noisyEvent(r, "admin", "login.locked", "", "")
		s.renderLogin(w, r, http.StatusTooManyRequests, "Too many failed attempts. Try again in 15 minutes.")
		return
	}
	hash, seed, _, err := s.store.Admin()
	ok := err == nil && auth.CheckPassword(hash, r.PostFormValue("password"))
	if ok && seed != nil {
		var step int64
		step, ok = auth.CheckTOTP(seed, r.PostFormValue("totp"), now)
		if ok {
			ok = s.store.UseTOTPStep(step) == nil // rejects a replayed code
		}
	}
	if !ok {
		s.event(r, "admin", "login.fail", "", "")
		msg := "Wrong password."
		if seed != nil {
			msg = "Wrong password or code."
		}
		s.renderLogin(w, r, http.StatusUnauthorized, msg)
		return
	}
	att.Succeed()
	s.event(r, "admin", "login", "", "")
	s.setDeviceCookie(w)
	s.newSession(w)
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request, sid string, se *session) {
	s.endSession(w, sid)
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

// ---- secrets ----

// varRow is a variable with its value, which the dashboard shows in full.
type varRow struct {
	store.Secret
	Value string
}

// navFor names the sidebar entry a path belongs to.
func navFor(path string) string {
	switch {
	case path == "/inbox":
		return "inbox"
	case strings.HasPrefix(path, "/groups"):
		return "groups"
	case strings.HasPrefix(path, "/tokens"), strings.HasPrefix(path, "/token/"), strings.HasPrefix(path, "/pair"):
		return "agents"
	case path == "/audit":
		return "log"
	case strings.HasPrefix(path, "/settings"):
		return "settings"
	}
	return "secrets"
}

// inboxCounts is what waits for the admin: request cards plus keys with
// open flags, notes or a proposal. summary says it in words.
func (s *Server) inboxCounts() (n int, summary string) {
	var pending []store.Secret
	for _, sec := range s.store.ListSecrets(func(sec *store.Secret) bool { return sec.Pending }) {
		pending = append(pending, sec)
	}
	reqs, attn := len(s.requestCards(pending)), len(s.attention())
	asked, _ := s.renewalViews()
	h, dropped := s.store.CanaryHits()
	hits := len(h)
	if dropped > 0 {
		hits++
	}
	var parts []string
	if hits > 0 {
		parts = append(parts, fmt.Sprintf("%d canary alert%s", hits, plural(hits)))
	}
	if len(asked) > 0 {
		parts = append(parts, fmt.Sprintf("%d renewal%s", len(asked), plural(len(asked))))
	}
	if reqs > 0 {
		parts = append(parts, fmt.Sprintf("%d request%s", reqs, plural(reqs)))
	}
	if attn > 0 {
		parts = append(parts, fmt.Sprintf("%d to review", attn))
	}
	return hits + len(asked) + reqs + attn, strings.Join(parts, ", ")
}

// attention is NeedsAttention without the requests still waiting for a
// value: their proposed description already shows on the request card.
func (s *Server) attention() []store.Attention {
	var out []store.Attention
	for _, a := range s.store.NeedsAttention() {
		if a.Pending && len(a.Flags) == 0 && len(a.Notes) == 0 {
			continue
		}
		out = append(out, a)
	}
	return out
}

func plural(n int) string {
	if n == 1 {
		return ""
	}
	return "s"
}

func (s *Server) handleDashboard(w http.ResponseWriter, r *http.Request, _ string, se *session) {
	s.renderDashboard(w, r, se, http.StatusOK, "")
}

// matches reports whether a search query q (already lower case) is found
// in an entry's name, namespace, description or group.
func matches(q string, sec store.Secret, assign map[string]store.GroupRef) bool {
	if q == "" {
		return true
	}
	hay := strings.ToLower(sec.Namespace + " " + sec.Name + " " + sec.Description + " " + assign[sec.Ref()].Name)
	return strings.Contains(hay, q)
}

func (s *Server) renderDashboard(w http.ResponseWriter, r *http.Request, se *session, status int, errMsg string) {
	query := strings.TrimSpace(r.URL.Query().Get("q"))
	if rs := []rune(query); len(rs) > 100 {
		query = string(rs[:100]) // by character, so none is cut in half
	}
	assign := s.store.GroupAssignments()
	var entries []store.Secret
	for _, sec := range s.store.ListSecrets(nil) {
		if !sec.Pending && matches(strings.ToLower(query), sec, assign) {
			entries = append(entries, sec)
		}
	}
	_, summary := s.inboxCounts()
	s.render(w, r, "dashboard", status, se, page{
		"Title": "Secrets", "Query": query, "Error": errMsg,
		"Sections":     s.arrange(entries, assign, true),
		"NoAgents":     len(s.store.ListTokens()) == 0,
		"InboxSummary": summary,
	})
}

func (s *Server) handleNew(w http.ResponseWriter, r *http.Request, _ string, se *session) {
	s.renderNew(w, r, se, http.StatusOK, "")
}

func (s *Server) renderNew(w http.ResponseWriter, r *http.Request, se *session, status int, errMsg string) {
	nss := s.store.Namespaces()
	def := ""
	if len(nss) == 1 {
		def = nss[0]
	}
	s.render(w, r, "new", status, se, page{"Title": "New", "Nav": "secrets", "Namespaces": nss, "DefaultNS": def, "Error": errMsg})
}

func (s *Server) handleInbox(w http.ResponseWriter, r *http.Request, _ string, se *session) {
	s.renderInbox(w, r, se, http.StatusOK, "")
}

func (s *Server) renderInbox(w http.ResponseWriter, r *http.Request, se *session, status int, errMsg string) {
	var pending []store.Secret
	for _, sec := range s.store.ListSecrets(func(sec *store.Secret) bool { return sec.Pending }) {
		pending = append(pending, sec)
	}
	asked, collecting := s.renewalViews()
	hits, dropped := s.store.CanaryHits()
	s.render(w, r, "inbox", status, se, page{
		"Title": "Inbox", "Nav": "inbox", "Error": errMsg,
		"CanaryHits": hits, "CanaryDropped": dropped, "Renewals": asked, "Collecting": collecting,
		"Cards": s.requestCards(pending), "Attention": s.attention(),
	})
}

// readValue reads a value field. It's trimmed (phone keyboards love a
// trailing space) unless "keep whitespace" or "save it exactly as pasted"
// is ticked. hint is set when the value looks like a paste mistake (see
// pasteMistake); ticking "save it exactly as pasted" skips that check.
func readValue(r *http.Request, field string) (val []byte, hint string) {
	v := r.PostFormValue(field)
	exact := r.PostFormValue("exact") == "yes"
	keep := exact || r.PostFormValue("keepws") == "yes"
	if !keep {
		v = strings.TrimSpace(v)
	}
	if !exact && v != "" {
		hint = pasteMistake(v, keep)
	}
	return []byte(v), hint
}

func parseDate(s string) (*time.Time, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil, nil
	}
	t, err := time.Parse("2006-01-02", s)
	if err != nil {
		t, err = time.Parse(time.RFC3339, s)
	}
	if err != nil {
		return nil, errors.New("expiry must be a date like 2027-01-23")
	}
	t = t.UTC()
	return &t, nil
}

// decoyValue is a random value for a canary left empty: 40 letters and
// digits, the shape of a typical API key.
func decoyValue() []byte {
	const chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
	b := make([]byte, 0, 40)
	var buf [64]byte
	for len(b) < cap(b) {
		if _, err := rand.Read(buf[:]); err != nil {
			panic(err) // crypto/rand never fails on supported platforms
		}
		for _, c := range buf {
			// 248 = 4*62: rejecting the rest keeps every character equally likely.
			if c < 248 && len(b) < cap(b) {
				b = append(b, chars[c%62])
			}
		}
	}
	return b
}

func formMeta(r *http.Request) (store.Meta, error) {
	exp, err := parseDate(r.PostFormValue("expires"))
	return store.Meta{
		Description: strings.TrimSpace(r.PostFormValue("description")),
		Usage:       strings.TrimSpace(r.PostFormValue("usage")),
		Expires:     exp,
		Variable:    r.PostFormValue("kind") == "variable",
	}, err
}

func (s *Server) handleCreateSecret(w http.ResponseWriter, r *http.Request, _ string, se *session) {
	ns, newNS := formNamespace(r, s.store.Namespaces())
	// Upper-cased so a phone keyboard's lower case still gives an env-style name.
	name := strings.ToUpper(strings.TrimSpace(r.PostFormValue("name")))
	val, hint := readValue(r, "value")
	meta, err := formMeta(r)
	// "Canary" is a third kind on the New page; the checkbox is the older form.
	canary := (r.PostFormValue("kind") == "canary" || r.PostFormValue("canary") == "yes") && !meta.Variable
	if canary && len(val) == 0 && hint == "" {
		// The value of a decoy doesn't matter, only that it looks real.
		val = decoyValue()
	}
	switch {
	case hint != "":
		s.renderNew(w, r, se, http.StatusBadRequest, hint+" Nothing was saved.")
		return
	case err != nil:
		s.renderNew(w, r, se, http.StatusBadRequest, err.Error())
		return
	case !store.ValidName(ns):
		s.renderNew(w, r, se, http.StatusBadRequest, "Namespace: lowercase letters, digits, '.', '_' and '-' only.")
		return
	case !store.ValidSecretName(name):
		s.renderNew(w, r, se, http.StatusBadRequest, "Name: like an environment variable, e.g. CLOUDFLARE_API_TOKEN (letters, digits and '_', not starting with a digit).")
		return
	case len(val) == 0:
		s.renderNew(w, r, se, http.StatusBadRequest, "The value is empty.")
		return
	}
	old, exists := s.store.GetSecret(ns, name)
	conflict := func() {
		s.renderNew(w, r, se, http.StatusConflict, ns+"/"+name+" already exists. Tick \"Replace it\" or open it to replace the value.")
	}
	overwrite := r.PostFormValue("overwrite") == "yes"
	if exists && old.HasValue() && !overwrite {
		conflict()
		return
	}
	put := s.store.PutValue
	if !overwrite {
		put = s.store.CreateValue
	}
	if err := put(ns, name, val, &meta); errors.Is(err, store.ErrExists) {
		conflict()
		return
	} else if err != nil {
		s.renderNew(w, r, se, http.StatusInternalServerError, err.Error())
		return
	}
	s.event(r, "admin", "secret.set", ns+"/"+name, "")
	if exists && old.Variable != meta.Variable {
		s.event(r, "admin", "secret.kind", ns+"/"+name, kindChange(meta.Variable))
	}
	if canary {
		if err := s.store.SetCanary(ns, name, true); err != nil {
			log.Printf("canary %s/%s: %v", ns, name, err)
		} else {
			s.event(r, "admin", "secret.canary", ns+"/"+name, "on")
		}
	}
	s.noteDups(se, ns+"/"+name)
	msg := "saved"
	if newNS {
		msg = "newns"
	}
	http.Redirect(w, r, "/secret/"+url.PathEscape(ns)+"/"+url.PathEscape(name)+"?msg="+msg, http.StatusSeeOther)
}

func (s *Server) handleSecret(w http.ResponseWriter, r *http.Request, _ string, se *session) {
	s.renderSecret(w, r, se, http.StatusOK, "")
}

func (s *Server) renderSecret(w http.ResponseWriter, r *http.Request, se *session, status int, errMsg string) {
	s.renderSecretWith(w, r, se, status, errMsg, "")
}

func (s *Server) renderSecretWith(w http.ResponseWriter, r *http.Request, se *session, status int, errMsg, value string) {
	ns, name := r.PathValue("ns"), r.PathValue("name")
	sec, ok := s.store.GetSecret(ns, name)
	if !ok {
		s.message(w, r, http.StatusNotFound, "Not found", "There's no secret called "+ns+"/"+name+".")
		return
	}
	if sec.Variable && sec.HasValue() {
		v, _ := s.store.VariableValue(ns, name)
		value = string(v)
	}
	var readers []string
	for _, t := range s.store.ListTokens() {
		if t.Allows(ns) {
			readers = append(readers, t.Name)
		}
	}
	ext := store.SecretExt{}
	if sec.Ext != nil {
		ext = *sec.Ext
	}
	s.render(w, r, "secret", status, se, page{
		"Title": sec.Ref(), "S": sec, "HasPrevious": len(sec.Previous) > 0,
		"Readers": readers, "Error": errMsg, "Value": value, "X": ext, "AlertsConfigured": s.alerts.configured(),
		"GroupList": s.store.Groups(ns), "InGroup": s.store.GroupAssignments()[sec.Ref()],
		"History": s.store.History(func(ev store.Event) bool { return ev.Namespace == ns && ev.Name == name }, 50),
	})
}

// handleReveal shows a value on the secret page. It's a POST, so the value
// never lands in a URL or browser history, and every view is logged.
func (s *Server) handleReveal(w http.ResponseWriter, r *http.Request, _ string, se *session) {
	ns, name := r.PathValue("ns"), r.PathValue("name")
	val, variable, err := s.store.Reveal(ns, name, "admin (web)")
	switch {
	case errors.Is(err, store.ErrNotFound):
		s.message(w, r, http.StatusNotFound, "Not found", "There's no secret called "+ns+"/"+name+".")
		return
	case errors.Is(err, store.ErrNoValue):
		s.renderSecret(w, r, se, http.StatusBadRequest, "There's no value to show yet.")
		return
	case err != nil:
		log.Printf("reveal %s/%s: %v", ns, name, err)
		s.renderSecret(w, r, se, http.StatusInternalServerError, "Couldn't decrypt the value. Check keydrop's log.")
		return
	}
	if !variable {
		s.event(r, "admin", "secret.reveal", ns+"/"+name, "web UI")
	}
	s.renderSecretWith(w, r, se, http.StatusOK, "", string(val))
}

func (s *Server) back(w http.ResponseWriter, r *http.Request, msg string) {
	http.Redirect(w, r, "/secret/"+url.PathEscape(r.PathValue("ns"))+"/"+url.PathEscape(r.PathValue("name"))+"?msg="+msg, http.StatusSeeOther)
}

func (s *Server) handleSetValue(w http.ResponseWriter, r *http.Request, _ string, se *session) {
	ns, name := r.PathValue("ns"), r.PathValue("name")
	sec, ok := s.store.GetSecret(ns, name)
	if !ok {
		s.message(w, r, http.StatusNotFound, "Not found", "There's no secret called "+ns+"/"+name+".")
		return
	}
	val, hint := readValue(r, "value")
	if hint != "" {
		s.renderSecret(w, r, se, http.StatusBadRequest, hint+" Nothing was saved.")
		return
	}
	if len(val) == 0 {
		s.renderSecret(w, r, se, http.StatusBadRequest, "The value is empty.")
		return
	}
	if err := s.store.PutValue(ns, name, val, nil); err != nil {
		s.renderSecret(w, r, se, http.StatusInternalServerError, err.Error())
		return
	}
	detail := ""
	switch {
	case sec.Pending && sec.RequestedBy != "":
		detail = "fulfilled request from " + sec.RequestedBy
	case sec.Pending:
		detail = "fulfilled request from a revoked token"
	}
	s.event(r, "admin", "secret.set", ns+"/"+name, detail)
	s.noteDups(se, ns+"/"+name)
	s.back(w, r, "saved")
}

func (s *Server) handleSetMeta(w http.ResponseWriter, r *http.Request, _ string, se *session) {
	meta, err := formMeta(r)
	if err != nil {
		s.renderSecret(w, r, se, http.StatusBadRequest, err.Error())
		return
	}
	ns, name := r.PathValue("ns"), r.PathValue("name")
	old, _ := s.store.GetSecret(ns, name)
	if err := s.store.UpdateMeta(ns, name, meta); err != nil {
		s.renderSecret(w, r, se, http.StatusNotFound, err.Error())
		return
	}
	if old.Variable != meta.Variable {
		s.event(r, "admin", "secret.kind", ns+"/"+name, kindChange(meta.Variable))
	}
	s.event(r, "admin", "secret.details", ns+"/"+name, "")
	s.back(w, r, "details")
}

func (s *Server) handleRollback(w http.ResponseWriter, r *http.Request, _ string, se *session) {
	ns, name := r.PathValue("ns"), r.PathValue("name")
	old, _ := s.store.GetSecret(ns, name)
	if err := s.store.Rollback(ns, name); err != nil {
		s.renderSecret(w, r, se, http.StatusBadRequest, err.Error())
		return
	}
	s.event(r, "admin", "secret.rollback", ns+"/"+name, "")
	if now, _ := s.store.GetSecret(ns, name); now.Variable != old.Variable {
		s.event(r, "admin", "secret.kind", ns+"/"+name, kindChange(now.Variable))
	}
	s.back(w, r, "rolledback")
}

func (s *Server) handleDelete(w http.ResponseWriter, r *http.Request, _ string, se *session) {
	ns, name := r.PathValue("ns"), r.PathValue("name")
	if r.PostFormValue("confirm") != "yes" {
		s.renderSecret(w, r, se, http.StatusBadRequest, "Tick the box to confirm.")
		return
	}
	if err := s.store.Delete(ns, name); err != nil {
		s.renderSecret(w, r, se, http.StatusNotFound, err.Error())
		return
	}
	s.event(r, "admin", "secret.delete", ns+"/"+name, "")
	http.Redirect(w, r, "/?msg=deleted", http.StatusSeeOther)
}

// ---- tokens ----

func (s *Server) handleTokens(w http.ResponseWriter, r *http.Request, _ string, se *session) {
	s.renderTokens(w, r, se, http.StatusOK, "")
}

// renderTokens shows an error where the form that caused it lives: the
// agent's own page for its forms, the Add an agent page for a new token,
// the list otherwise.
func (s *Server) renderTokens(w http.ResponseWriter, r *http.Request, se *session, status int, errMsg string) {
	s.sweepRotations(s.now())
	if r.Method == http.MethodPost && r.URL.Path == "/tokens" {
		s.renderNewAgent(w, r, se, status, errMsg)
		return
	}
	if name := r.PathValue("name"); name != "" {
		if v, ok := s.tokenView(name); ok {
			s.render(w, r, "token", status, se, page{"Title": name, "T": &v, "Namespaces": s.store.Namespaces(), "Error": errMsg})
			return
		}
	}
	s.render(w, r, "tokens", status, se, page{"Title": "Agents", "Tokens": s.tokenViews(), "Pairings": s.pendingPairings(), "Error": errMsg})
}

func (s *Server) tokenView(name string) (tokenView, bool) {
	for _, v := range s.tokenViews() {
		if v.Name == name {
			return v, true
		}
	}
	return tokenView{}, false
}

// handleToken is one agent's page, where its settings are changed.
func (s *Server) handleToken(w http.ResponseWriter, r *http.Request, _ string, se *session) {
	if _, ok := s.tokenView(r.PathValue("name")); !ok {
		s.renderTokens(w, r, se, http.StatusNotFound, "There's no agent called "+r.PathValue("name")+".")
		return
	}
	s.renderTokens(w, r, se, http.StatusOK, "")
}

func (s *Server) handleNewAgent(w http.ResponseWriter, r *http.Request, _ string, se *session) {
	s.renderNewAgent(w, r, se, http.StatusOK, "")
}

func (s *Server) renderNewAgent(w http.ResponseWriter, r *http.Request, se *session, status int, errMsg string) {
	public, direct := s.cfg.InstallCommands()
	s.render(w, r, "token_new", status, se, page{"Title": "Add an agent", "Namespaces": s.store.Namespaces(), "DefaultLifetime": store.DefaultTokenLifetime, "Error": errMsg,
		"InstallPublic": public, "InstallDirect": direct, "CLI": s.cfg.CLI, "CertPin": s.cfg.CertPin, "Version": s.cfg.Version})
}

func splitList(s string) []string {
	var out []string
	for _, f := range strings.FieldsFunc(s, func(c rune) bool { return c == ',' || c == ' ' }) {
		out = append(out, strings.TrimSpace(f))
	}
	return out
}

func (s *Server) handleCreateToken(w http.ResponseWriter, r *http.Request, _ string, se *session) {
	name := strings.TrimSpace(r.PostFormValue("name"))
	nss := formNamespaces(r)
	perm, ok := formPermission(url.Values{"permission": {r.PostFormValue("permission")}, "write": {r.PostFormValue("write")}})
	if !ok {
		s.renderTokens(w, r, se, http.StatusBadRequest, "Permission: read, add or write.")
		return
	}
	sources, err := store.ParseSources(r.PostFormValue("sources"))
	if err != nil {
		s.renderTokens(w, r, se, http.StatusBadRequest, "Allowed from: "+err.Error()+".")
		return
	}
	days, err := formLifetime(r)
	if err != nil {
		s.renderTokens(w, r, se, http.StatusBadRequest, "New token every: "+err.Error()+".")
		return
	}
	tok, err := s.store.CreateTokenExpiring(name, nss, perm, sources, days)
	if err != nil {
		msg := err.Error()
		if errors.Is(err, store.ErrExists) {
			msg = "An agent called " + name + " already exists. Revoke it first to make a new token."
		}
		s.renderTokens(w, r, se, http.StatusBadRequest, msg)
		return
	}
	detail := "namespaces " + strings.Join(nss, ",") + ", " + string(perm)
	detail += ", allowed from " + sourcesText(sources) + ", " + lifetimeLabel(days)
	s.event(r, "admin", "token.create", name, detail)
	u := s.cfg.PublicURL
	if u == "" {
		u = "https://" + r.Host
	}
	s.render(w, r, "token_created", http.StatusOK, se, page{"Title": "New token", "Name": name, "Token": tok, "URL": u})
}

func (s *Server) handleRevokeToken(w http.ResponseWriter, r *http.Request, _ string, se *session) {
	name := r.PathValue("name")
	if r.PostFormValue("confirm") != "yes" {
		s.renderTokens(w, r, se, http.StatusBadRequest, "Tick the box to confirm.")
		return
	}
	if err := s.store.RevokeToken(name); err != nil {
		s.renderTokens(w, r, se, http.StatusNotFound, err.Error())
		return
	}
	s.event(r, "admin", "token.revoke", name, "")
	http.Redirect(w, r, "/tokens?msg=revoked", http.StatusSeeOther)
}

// auditPage is how many events the Log shows at a time.
const auditPage = 50

// handleAudit is the Log: the events kept in memory, filtered, sorted and
// split into pages by query parameters, so it works without scripts.
//
//	q     text in any field (case-insensitive)
//	who   an actor, or "-" for requests without a credential
//	what  an action's first part ("secret", "token", ...)
//	sort  "old" for oldest first
//	page  1, 2, ...
func (s *Server) handleAudit(w http.ResponseWriter, r *http.Request, _ string, se *session) {
	qv := r.URL.Query()
	q, who, what := strings.TrimSpace(qv.Get("q")), qv.Get("who"), qv.Get("what")
	old := qv.Get("sort") == "old"
	all := s.audit.Recent(2 * auditKept)
	whos, whats := map[string]bool{}, map[string]bool{}
	var events []audit.Event
	for _, e := range all {
		whos[e.Actor] = true
		whats[actionKind(e.Action)] = true
		switch {
		case who == "-" && !e.Unauthenticated,
			who != "" && who != "-" && e.Actor != who,
			what != "" && actionKind(e.Action) != what,
			q != "" && !eventHas(e, q):
			continue
		}
		events = append(events, e)
	}
	if old {
		slices.Reverse(events)
	}
	pages := max(1, (len(events)+auditPage-1)/auditPage)
	n, _ := strconv.Atoi(qv.Get("page"))
	n = min(max(n, 1), pages)
	shown := events[(n-1)*auditPage : min(n*auditPage, len(events))]

	// link is this view with some parameters changed; empty ones are dropped.
	link := func(kv ...string) string {
		v := url.Values{}
		for k, x := range map[string]string{"q": q, "who": who, "what": what, "sort": qv.Get("sort")} {
			if x != "" {
				v.Set(k, x)
			}
		}
		for i := 0; i+1 < len(kv); i += 2 {
			if kv[i+1] == "" {
				v.Del(kv[i])
			} else {
				v.Set(kv[i], kv[i+1])
			}
		}
		if len(v) == 0 {
			return "/audit"
		}
		return "/audit?" + v.Encode()
	}
	data := page{"Title": "Log", "Events": shown, "Q": q, "Who": who, "What": what, "Old": old,
		"Whos": setKeys(whos), "Whats": setKeys(whats), "Total": len(all), "Matched": len(events),
		"Filtered": q != "" || who != "" || what != "", "Page": n, "Pages": pages,
		"SortLink": link("sort", map[bool]string{false: "old", true: ""}[old], "page", "")}
	if n > 1 {
		data["Prev"] = link("page", strconv.Itoa(n-1))
	}
	if n < pages {
		data["Next"] = link("page", strconv.Itoa(n+1))
	}
	s.render(w, r, "audit", http.StatusOK, se, data)
}

// auditKept matches what the audit log keeps in memory of each kind.
const auditKept = 500

// actionKind is an action's first part: "secret" for "secret.read".
func actionKind(a string) string {
	k, _, _ := strings.Cut(a, ".")
	return k
}

func eventHas(e audit.Event, q string) bool {
	q = strings.ToLower(q)
	for _, f := range []string{e.Actor, e.Action, e.Target, e.Detail, e.Text, e.IP} {
		if strings.Contains(strings.ToLower(f), q) {
			return true
		}
	}
	return false
}

func setKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	slices.Sort(out)
	return out
}

// ---- settings ----

func (s *Server) handleSettings(w http.ResponseWriter, r *http.Request, _ string, se *session) {
	s.renderSettings(w, r, se, http.StatusOK, "")
}

func (s *Server) renderSettings(w http.ResponseWriter, r *http.Request, se *session, status int, errMsg string) {
	on := s.store.TOTPEnabled()
	s.mu.Lock()
	seed := se.newTOTP
	s.mu.Unlock()
	data := page{}
	if !on && seed != nil {
		data = s.otpView(seed)
	}
	data["Title"], data["TOTP"], data["Error"] = "Settings", on, errMsg
	data["AutoGroups"] = s.store.AutoGroups()
	data["Themes"] = themes
	data["Version"] = s.cfg.Version
	data["Build"] = s.buildInfo()
	data["AlertsConfigured"] = s.alerts.configured()
	data["AlertDest"] = s.alerts.destination(false)
	data["AlertSource"], data["AlertSetAt"] = s.alertSource()
	data["AlertEnv"] = s.cfg.AlertWebhook != ""
	data["RevokeOnCanary"] = s.store.RevokeOnCanary()
	s.render(w, r, "settings", status, se, data)
}

// buildInfo is the version line's detail: a link to the commit, when it was
// committed and when this server started. Fields are empty when unknown.
func (s *Server) buildInfo() map[string]string {
	b := map[string]string{"Started": fmtAgo(s.started, s.now())}
	if t, err := time.Parse(time.RFC3339, s.cfg.CommitTime); err == nil {
		b["Committed"] = fmtAgo(t, s.now())
	}
	if commitHash.MatchString(s.cfg.Commit) {
		if u, err := url.Parse(s.cfg.RepoURL); err == nil && (u.Scheme == "https" || u.Scheme == "http") && u.Host != "" {
			b["CommitURL"] = strings.TrimRight(s.cfg.RepoURL, "/") + "/commit/" + s.cfg.Commit
		}
	}
	return b
}

var commitHash = regexp.MustCompile(`^[0-9a-f]{7,64}$`)

// fmtAgo is a local date and time with how long ago it was.
func fmtAgo(t, now time.Time) string {
	return t.Local().Format("2006-01-02 15:04") + " (" + humanAgo(now.Sub(t)) + ")"
}

// handleTOTPStart makes a new seed for this session and shows it. Nothing
// changes until a code from it is confirmed.
func (s *Server) handleTOTPStart(w http.ResponseWriter, r *http.Request, _ string, se *session) {
	if !s.store.TOTPEnabled() {
		s.mu.Lock()
		se.newTOTP = auth.NewTOTPSecret()
		s.mu.Unlock()
	}
	s.renderSettings(w, r, se, http.StatusOK, "")
}

// confirmPassword checks the admin password typed into a settings form,
// against the same limiter as login, so a stolen session can't be used to
// guess it. It renders the error itself and returns false on failure.
func (s *Server) confirmPassword(w http.ResponseWriter, r *http.Request, se *session, field, why string) bool {
	att, err := s.tryLogin(r)
	if err != nil {
		s.renderSettings(w, r, se, http.StatusTooManyRequests, "Too many failed attempts. Try again in 15 minutes.")
		return false
	}
	hash, _, _, err := s.store.Admin()
	if err != nil || !auth.CheckPassword(hash, r.PostFormValue(field)) {
		s.event(r, "admin", "admin.password.fail", "", why)
		msg := "Wrong password."
		if field == "current" {
			msg = "The current password is wrong."
		}
		s.renderSettings(w, r, se, http.StatusUnauthorized, msg)
		return false
	}
	att.Succeed()
	return true
}

// handleTOTPOn needs the password as well as a code, like turning it off,
// so an unattended logged-in phone can't bind someone else's authenticator.
func (s *Server) handleTOTPOn(w http.ResponseWriter, r *http.Request, _ string, se *session) {
	s.mu.Lock()
	seed := se.newTOTP
	s.mu.Unlock()
	if seed == nil || s.store.TOTPEnabled() {
		http.Redirect(w, r, "/settings", http.StatusSeeOther)
		return
	}
	if !s.confirmPassword(w, r, se, "password", "turning on the authenticator") {
		return
	}
	step, ok := auth.CheckTOTP(seed, r.PostFormValue("totp"), s.now())
	if !ok {
		s.renderSettings(w, r, se, http.StatusBadRequest, "That code didn't match. Check the keydrop entry in the app and try again.")
		return
	}
	if err := s.store.SetTOTP(seed); err != nil {
		log.Printf("totp on: %v", err)
		s.renderSettings(w, r, se, http.StatusInternalServerError, "Couldn't save. Check keydrop's log.")
		return
	}
	_ = s.store.UseTOTPStep(step) // fails only if this code was already used
	s.mu.Lock()
	se.newTOTP = nil
	s.mu.Unlock()
	s.event(r, "admin", "admin.totp.on", "", "")
	http.Redirect(w, r, "/settings?msg=totpon", http.StatusSeeOther)
}

// handlePassword changes the admin password. It needs the current one (an
// unattended logged-in phone shouldn't be enough), and it logs out every
// other session, in case the old password is why you're changing it.
func (s *Server) handlePassword(w http.ResponseWriter, r *http.Request, _ string, se *session) {
	if !s.confirmPassword(w, r, se, "current", "wrong current password") {
		return
	}
	pw := r.PostFormValue("password")
	switch {
	case len([]rune(pw)) < auth.MinPasswordLength:
		s.renderSettings(w, r, se, http.StatusBadRequest, fmt.Sprintf("The new password needs at least %d characters.", auth.MinPasswordLength))
		return
	case pw != r.PostFormValue("password2"):
		s.renderSettings(w, r, se, http.StatusBadRequest, "The new passwords don't match.")
		return
	}
	newHash, err := auth.HashPassword(pw)
	if err == nil {
		err = s.store.SetPassword(newHash)
	}
	if err != nil {
		log.Printf("change password: %v", err)
		s.renderSettings(w, r, se, http.StatusInternalServerError, "Couldn't save. Check keydrop's log.")
		return
	}
	// End every session, this one included, and start a fresh one: if the
	// leak being reacted to is this session's own cookie, it must die too.
	s.mu.Lock()
	clear(s.sessions)
	s.mu.Unlock()
	s.newSession(w)
	s.event(r, "admin", "admin.password", "", "")
	http.Redirect(w, r, "/settings?msg=password", http.StatusSeeOther)
}

// handleTOTPOff needs the password again, so an unattended logged-in phone
// can't quietly weaken the login.
func (s *Server) handleTOTPOff(w http.ResponseWriter, r *http.Request, _ string, se *session) {
	if !s.confirmPassword(w, r, se, "password", "turning off the authenticator") {
		return
	}
	if err := s.store.SetTOTP(nil); err != nil {
		log.Printf("totp off: %v", err)
		s.renderSettings(w, r, se, http.StatusInternalServerError, "Couldn't save. Check keydrop's log.")
		return
	}
	s.event(r, "admin", "admin.totp.off", "", "")
	http.Redirect(w, r, "/settings?msg=totpoff", http.StatusSeeOther)
}

func kindChange(variable bool) string {
	if variable {
		return "now a variable"
	}
	return "now a secret"
}

// ---- status, flags, notes and proposals ----

// annotated runs an admin action on a key and goes back to its page, or
// shows the error there.
func (s *Server) annotated(w http.ResponseWriter, r *http.Request, se *session, err error, action, detail, msg string) {
	ns, name := r.PathValue("ns"), r.PathValue("name")
	switch {
	case errors.Is(err, store.ErrNotFound):
		if _, ok := s.store.GetSecret(ns, name); !ok {
			s.message(w, r, http.StatusNotFound, "Not found", "There's no secret called "+ns+"/"+name+".")
			return
		}
		s.renderSecret(w, r, se, http.StatusNotFound, "That was already dealt with.")
		return
	case err != nil:
		s.renderSecret(w, r, se, http.StatusBadRequest, err.Error())
		return
	}
	s.event(r, "admin", action, ns+"/"+name, detail)
	s.back(w, r, msg)
}

func (s *Server) handleSetStatus(w http.ResponseWriter, r *http.Request, _ string, se *session) {
	value, repl := r.PostFormValue("status"), strings.ToUpper(strings.TrimSpace(r.PostFormValue("replaced_by")))
	if value != "replaced-by" {
		repl = ""
	}
	err := s.store.SetStatus(r.PathValue("ns"), r.PathValue("name"), value, repl, "admin")
	detail := value
	if repl != "" {
		detail += " " + repl
	}
	s.annotated(w, r, se, err, "secret.status", detail, "status")
}

func (s *Server) handleResolveFlag(w http.ResponseWriter, r *http.Request, _ string, se *session) {
	err := s.store.ResolveFlag(r.PathValue("ns"), r.PathValue("name"), r.PathValue("id"))
	s.annotated(w, r, se, err, "secret.flag.resolve", "", "resolved")
}

func (s *Server) handleApproveNote(w http.ResponseWriter, r *http.Request, _ string, se *session) {
	err := s.store.ApproveNote(r.PathValue("ns"), r.PathValue("name"), r.PathValue("id"), r.PostFormValue("text"))
	s.annotated(w, r, se, err, "secret.note.approve", "", "approved")
}

func (s *Server) handleRemoveNote(w http.ResponseWriter, r *http.Request, _ string, se *session) {
	err := s.store.RemoveNote(r.PathValue("ns"), r.PathValue("name"), r.PathValue("id"))
	s.annotated(w, r, se, err, "secret.note.remove", "", "rejected")
}

func (s *Server) handleApproveProposal(w http.ResponseWriter, r *http.Request, _ string, se *session) {
	err := s.store.ApproveProposal(r.PathValue("ns"), r.PathValue("name"), r.PostFormValue("version"), r.PostFormValue("description"), r.PostFormValue("usage"))
	s.annotated(w, r, se, err, "secret.proposal.approve", "", "approved")
}

func (s *Server) handleRejectProposal(w http.ResponseWriter, r *http.Request, _ string, se *session) {
	err := s.store.RejectProposal(r.PathValue("ns"), r.PathValue("name"), r.PostFormValue("version"))
	s.annotated(w, r, se, err, "secret.proposal.reject", "", "rejected")
}
