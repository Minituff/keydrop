package server

import (
	"crypto/subtle"
	"embed"
	"errors"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/minituff/keydrop/internal/audit"
	"github.com/minituff/keydrop/internal/auth"
	"github.com/minituff/keydrop/internal/notify"
	"github.com/minituff/keydrop/internal/store"
)

//go:embed web
var webFS embed.FS

type expiryInfo struct{ Text, Class string }

var funcs = template.FuncMap{
	"join": strings.Join,
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
	for _, p := range []string{"setup", "login", "dashboard", "secret", "tokens", "token_created", "audit", "message"} {
		pages[p] = template.Must(template.New("").Funcs(funcs).ParseFS(webFS, "web/layout.html", "web/"+p+".html"))
	}
}

// Fixed flash messages, picked by key so a link can't inject arbitrary text.
var flashes = map[string]string{
	"saved":      "Saved. The value can't be shown again.",
	"details":    "Details saved.",
	"rolledback": "Rolled back to the previous value.",
	"deleted":    "Deleted.",
	"revoked":    "Token revoked.",
}

type page map[string]any

func (s *Server) render(w http.ResponseWriter, r *http.Request, name string, status int, se *session, data page) {
	if data == nil {
		data = page{}
	}
	if se != nil {
		data["CSRF"] = se.csrf
	}
	if f, ok := flashes[r.URL.Query().Get("msg")]; ok {
		data["Flash"] = f
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	if err := pages[name].ExecuteTemplate(w, "layout", data); err != nil {
		log.Printf("render %s: %v", name, err)
	}
}

func (s *Server) message(w http.ResponseWriter, r *http.Request, status int, title, msg string) {
	s.render(w, r, "message", status, nil, page{"Title": title, "Message": msg})
}

func (s *Server) handleCSS(w http.ResponseWriter, r *http.Request) {
	b, _ := webFS.ReadFile("web/style.css")
	w.Header().Set("Content-Type", "text/css; charset=utf-8")
	w.Header().Set("Cache-Control", "public, max-age=3600")
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

func (s *Server) checkSetupToken(tok string) bool {
	s.setupMu.Lock()
	defer s.setupMu.Unlock()
	return s.setupToken != "" && subtle.ConstantTimeCompare([]byte(tok), []byte(s.setupToken)) == 1
}

func (s *Server) handleSetupForm(w http.ResponseWriter, r *http.Request) {
	if !s.setupOpen() {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	tok := r.URL.Query().Get("token")
	if !s.checkSetupToken(tok) {
		s.message(w, r, http.StatusForbidden, "Setup link needed", "Open the setup link printed in the container log.")
		return
	}
	s.renderSetup(w, r, tok, "")
}

func (s *Server) renderSetup(w http.ResponseWriter, r *http.Request, tok, errMsg string) {
	status := http.StatusOK
	if errMsg != "" {
		status = http.StatusBadRequest
	}
	s.render(w, r, "setup", status, nil, page{
		"Title": "Set up", "Token": tok, "Error": errMsg,
		"OTPSecret": auth.TOTPBase32(s.setupSeed),
		// Built here from fixed parts and a base32 seed, so it's safe to mark
		// as a URL (html/template would otherwise blank the otpauth: scheme).
		"OTPURI": template.URL(auth.TOTPURI(s.setupSeed, "keydrop", "admin")),
	})
}

func (s *Server) handleSetup(w http.ResponseWriter, r *http.Request) {
	tok := r.PostFormValue("token")
	if crossSite(r) || !s.checkSetupToken(tok) {
		s.message(w, r, http.StatusForbidden, "Setup link needed", "Open the setup link printed in the container log.")
		return
	}
	pw, pw2 := r.PostFormValue("password"), r.PostFormValue("password2")
	switch {
	case len([]rune(pw)) < auth.MinPasswordLength:
		s.renderSetup(w, r, tok, fmt.Sprintf("The password needs at least %d characters.", auth.MinPasswordLength))
		return
	case pw != pw2:
		s.renderSetup(w, r, tok, "The passwords don't match.")
		return
	}
	step, ok := auth.CheckTOTP(s.setupSeed, r.PostFormValue("code"), s.now())
	if !ok {
		s.renderSetup(w, r, tok, "That code didn't match. Check the authenticator entry and try again.")
		return
	}
	hash, err := auth.HashPassword(pw)
	if err == nil {
		err = s.store.SetAdmin(hash, s.setupSeed)
	}
	if err == nil {
		err = s.store.UseTOTPStep(step)
	}
	if err != nil {
		log.Printf("setup: %v", err)
		s.renderSetup(w, r, tok, "Couldn't save the admin login. Check the container log.")
		return
	}
	s.setupMu.Lock()
	s.setupToken, s.setupSeed = "", nil
	s.setupMu.Unlock()
	s.mu.Lock()
	s.sessions = map[string]*session{} // a reset logs everyone out
	s.mu.Unlock()
	s.event(r, "admin", "admin.setup", "", "")
	s.newSession(w)
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func (s *Server) handleLoginForm(w http.ResponseWriter, r *http.Request) {
	if !s.store.AdminConfigured() {
		s.message(w, r, http.StatusServiceUnavailable, "Not set up yet", "Open the setup link printed in the container log.")
		return
	}
	s.render(w, r, "login", http.StatusOK, nil, page{"Title": "Log in"})
}

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	ip := s.clientIP(r)
	now := s.now()
	if crossSite(r) {
		http.Error(w, "cross-site request refused", http.StatusForbidden)
		return
	}
	if err := s.limiter.Allow(ip, now); err != nil {
		s.event(r, "admin", "login.locked", "", "")
		s.render(w, r, "login", http.StatusTooManyRequests, nil, page{"Title": "Log in", "Error": "Too many failed attempts. Try again in 15 minutes."})
		return
	}
	hash, seed, _, err := s.store.Admin()
	ok := err == nil && auth.CheckPassword(hash, r.PostFormValue("password"))
	var step int64
	if ok {
		step, ok = auth.CheckTOTP(seed, r.PostFormValue("code"), now)
	}
	if ok {
		ok = s.store.UseTOTPStep(step) == nil // rejects a replayed code
	}
	if !ok {
		s.limiter.Fail(ip, now)
		s.event(r, "admin", "login.fail", "", "")
		s.render(w, r, "login", http.StatusUnauthorized, nil, page{"Title": "Log in", "Error": "Wrong password or code."})
		return
	}
	s.limiter.Succeed(ip)
	s.event(r, "admin", "login", "", "")
	s.newSession(w)
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request, sid string, se *session) {
	s.endSession(w, sid)
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

// ---- secrets ----

type group struct {
	Namespace string
	Secrets   []store.Secret
}

func (s *Server) handleDashboard(w http.ResponseWriter, r *http.Request, _ string, se *session) {
	s.renderDashboard(w, r, se, http.StatusOK, "")
}

func (s *Server) renderDashboard(w http.ResponseWriter, r *http.Request, se *session, status int, errMsg string) {
	var pending []store.Secret
	var groups []group
	for _, sec := range s.store.ListSecrets(nil) {
		if sec.Pending {
			pending = append(pending, sec)
			continue
		}
		if len(groups) == 0 || groups[len(groups)-1].Namespace != sec.Namespace {
			groups = append(groups, group{Namespace: sec.Namespace})
		}
		groups[len(groups)-1].Secrets = append(groups[len(groups)-1].Secrets, sec)
	}
	nss := s.store.Namespaces()
	def := ""
	if len(nss) == 1 {
		def = nss[0]
	}
	s.render(w, r, "dashboard", status, se, page{
		"Title": "Secrets", "Pending": pending, "Groups": groups,
		"Namespaces": nss, "DefaultNS": def, "Error": errMsg,
	})
}

func formValue(r *http.Request) []byte {
	v := r.PostFormValue("value")
	if r.PostFormValue("keepws") != "yes" {
		v = strings.TrimSpace(v) // phone keyboards love adding a trailing space
	}
	return []byte(v)
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

func formMeta(r *http.Request) (store.Meta, error) {
	exp, err := parseDate(r.PostFormValue("expires"))
	return store.Meta{
		Description: strings.TrimSpace(r.PostFormValue("description")),
		Usage:       strings.TrimSpace(r.PostFormValue("usage")),
		Expires:     exp,
	}, err
}

func (s *Server) handleCreateSecret(w http.ResponseWriter, r *http.Request, _ string, se *session) {
	ns := strings.TrimSpace(r.PostFormValue("namespace"))
	name := strings.TrimSpace(r.PostFormValue("name"))
	val := formValue(r)
	meta, err := formMeta(r)
	switch {
	case err != nil:
		s.renderDashboard(w, r, se, http.StatusBadRequest, err.Error())
		return
	case !store.ValidName(ns) || !store.ValidName(name):
		s.renderDashboard(w, r, se, http.StatusBadRequest, "Namespace and name: lowercase letters, digits, '.', '_' and '-' only.")
		return
	case len(val) == 0:
		s.renderDashboard(w, r, se, http.StatusBadRequest, "The value is empty.")
		return
	}
	if old, ok := s.store.GetSecret(ns, name); ok && old.HasValue() && r.PostFormValue("overwrite") != "yes" {
		s.renderDashboard(w, r, se, http.StatusConflict, ns+"/"+name+" already exists. Tick \"Replace it\" or open it to replace the value.")
		return
	}
	if err := s.store.PutValue(ns, name, val, &meta); err != nil {
		s.renderDashboard(w, r, se, http.StatusInternalServerError, err.Error())
		return
	}
	s.event(r, "admin", "secret.set", ns+"/"+name, "")
	s.cfg.Notifier.Send(notify.Event{Event: "secret.set", Namespace: ns, Name: name, Description: meta.Description, By: "admin", URL: s.secretURL(ns, name)})
	http.Redirect(w, r, "/secret/"+url.PathEscape(ns)+"/"+url.PathEscape(name)+"?msg=saved", http.StatusSeeOther)
}

func (s *Server) handleSecret(w http.ResponseWriter, r *http.Request, _ string, se *session) {
	s.renderSecret(w, r, se, http.StatusOK, "")
}

func (s *Server) renderSecret(w http.ResponseWriter, r *http.Request, se *session, status int, errMsg string) {
	ns, name := r.PathValue("ns"), r.PathValue("name")
	sec, ok := s.store.GetSecret(ns, name)
	if !ok {
		s.message(w, r, http.StatusNotFound, "Not found", "There's no secret called "+ns+"/"+name+".")
		return
	}
	var readers []string
	for _, t := range s.store.ListTokens() {
		if t.Allows(ns) {
			readers = append(readers, t.Name)
		}
	}
	s.render(w, r, "secret", status, se, page{
		"Title": sec.Ref(), "S": sec, "HasPrevious": len(sec.Previous) > 0,
		"Readers": readers, "Error": errMsg,
	})
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
	val := formValue(r)
	if len(val) == 0 {
		s.renderSecret(w, r, se, http.StatusBadRequest, "The value is empty.")
		return
	}
	if err := s.store.PutValue(ns, name, val, nil); err != nil {
		s.renderSecret(w, r, se, http.StatusInternalServerError, err.Error())
		return
	}
	detail := ""
	if sec.Pending {
		detail = "fulfilled request from " + sec.RequestedBy
	}
	s.event(r, "admin", "secret.set", ns+"/"+name, detail)
	s.cfg.Notifier.Send(notify.Event{Event: "secret.set", Namespace: ns, Name: name, Description: sec.Description, By: "admin", URL: s.secretURL(ns, name)})
	s.back(w, r, "saved")
}

func (s *Server) handleSetMeta(w http.ResponseWriter, r *http.Request, _ string, se *session) {
	meta, err := formMeta(r)
	if err != nil {
		s.renderSecret(w, r, se, http.StatusBadRequest, err.Error())
		return
	}
	ns, name := r.PathValue("ns"), r.PathValue("name")
	if err := s.store.UpdateMeta(ns, name, meta); err != nil {
		s.renderSecret(w, r, se, http.StatusNotFound, err.Error())
		return
	}
	s.event(r, "admin", "secret.details", ns+"/"+name, "")
	s.back(w, r, "details")
}

func (s *Server) handleRollback(w http.ResponseWriter, r *http.Request, _ string, se *session) {
	ns, name := r.PathValue("ns"), r.PathValue("name")
	if err := s.store.Rollback(ns, name); err != nil {
		s.renderSecret(w, r, se, http.StatusBadRequest, err.Error())
		return
	}
	s.event(r, "admin", "secret.rollback", ns+"/"+name, "")
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
	s.render(w, r, "tokens", http.StatusOK, se, page{"Title": "Agents", "Tokens": s.store.ListTokens()})
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
	nss := splitList(r.PostFormValue("namespaces"))
	write := r.PostFormValue("write") == "yes"
	tok, err := s.store.CreateToken(name, nss, write)
	if err != nil {
		msg := err.Error()
		if errors.Is(err, store.ErrExists) {
			msg = "An agent called " + name + " already exists. Revoke it first to make a new token."
		}
		s.render(w, r, "tokens", http.StatusBadRequest, se, page{"Title": "Agents", "Tokens": s.store.ListTokens(), "Error": msg})
		return
	}
	detail := "namespaces " + strings.Join(nss, ",")
	if write {
		detail += ", write"
	}
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
		s.render(w, r, "tokens", http.StatusBadRequest, se, page{"Title": "Agents", "Tokens": s.store.ListTokens(), "Error": "Tick the box to confirm."})
		return
	}
	if err := s.store.RevokeToken(name); err != nil {
		s.render(w, r, "tokens", http.StatusNotFound, se, page{"Title": "Agents", "Tokens": s.store.ListTokens(), "Error": err.Error()})
		return
	}
	s.event(r, "admin", "token.revoke", name, "")
	http.Redirect(w, r, "/tokens?msg=revoked", http.StatusSeeOther)
}

func (s *Server) handleAudit(w http.ResponseWriter, r *http.Request, _ string, se *session) {
	s.render(w, r, "audit", http.StatusOK, se, page{"Title": "Log", "Events": s.audit.Recent(300)})
}
