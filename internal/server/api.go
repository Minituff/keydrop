package server

import (
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/minituff/keydrop/internal/store"
)

// APISecret is the metadata agents see. It includes the value only for a
// variable; a secret's value comes only from the reveal endpoint.
type APISecret struct {
	Ref         string     `json:"ref"`
	Namespace   string     `json:"namespace"`
	Name        string     `json:"name"`
	Kind        string     `json:"kind"`
	Value       *string    `json:"value,omitempty"`
	Description string     `json:"description,omitempty"`
	Usage       string     `json:"usage,omitempty"`
	Expires     *time.Time `json:"expires,omitempty"`
	HasValue    bool       `json:"has_value"`
	Pending     bool       `json:"pending"`
	RequestedBy string     `json:"requested_by,omitempty"`
	New         bool       `json:"new"`
	UpdatedAt   time.Time  `json:"updated_at"`
	LastReadAt  *time.Time `json:"last_read_at,omitempty"`
	LastReadBy  string     `json:"last_read_by,omitempty"`
}

// toAPI shapes a secret for token tok; "new" is relative to that token.
func (s *Server) toAPI(sec store.Secret, tok string) APISecret {
	a := APISecret{
		Ref: sec.Ref(), Namespace: sec.Namespace, Name: sec.Name, Kind: sec.Kind(),
		Description: sec.Description, Usage: sec.Usage, Expires: sec.Expires,
		HasValue: sec.HasValue(), Pending: sec.Pending, RequestedBy: sec.RequestedBy,
		New: sec.NewFor(tok), UpdatedAt: sec.UpdatedAt, LastReadAt: sec.LastReadAt, LastReadBy: sec.LastReadBy,
	}
	if sec.Variable && sec.HasValue() {
		if v, err := s.store.VariableValue(sec.Namespace, sec.Name); err == nil {
			str := string(v)
			a.Value = &str
		}
	}
	return a
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

func apiError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}

type agentHandler func(w http.ResponseWriter, r *http.Request, t store.Token)

// agent requires a valid bearer token.
func (s *Server) agent(h agentHandler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		raw, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
		if !ok {
			apiError(w, http.StatusUnauthorized, "missing bearer token")
			return
		}
		ip := s.clientIP(r)
		t, err := s.store.LookupToken(strings.TrimSpace(raw), ip)
		switch {
		case errors.Is(err, store.ErrSource):
			s.event(r, actor(t), "token.denied", "", "not an allowed source")
			apiError(w, http.StatusForbidden, "token "+t.Name+" isn't allowed from "+ip+"; if that's expected, the admin can add it under Agents")
			return
		case err != nil:
			s.noisyEvent(r, "unknown", "api.badtoken", "", "")
			apiError(w, http.StatusUnauthorized, "invalid token")
			return
		}
		// Agents sharing a token (Claude and Codex on one box) can say which
		// one is acting. It's a label for the log, not an identity.
		if l := strings.ToLower(r.Header.Get("X-Keydrop-Agent")); store.ValidName(l) {
			t.Label = l
		}
		// Only for authenticated agents, so the version isn't announced to
		// anyone who connects.
		if s.cfg.Version != "" {
			w.Header().Set("X-Keydrop-Version", s.cfg.Version)
		}
		h(w, r, t)
	}
}

func actor(t store.Token) string {
	if t.Label != "" {
		return "token:" + t.Name + " (" + t.Label + ")"
	}
	return "token:" + t.Name
}

// lookup returns the secret only if the token may see its namespace. A
// namespace the token isn't granted looks exactly like a missing secret.
func (s *Server) lookup(w http.ResponseWriter, r *http.Request, t store.Token) (store.Secret, bool) {
	ns, name := r.PathValue("ns"), r.PathValue("name")
	sec, ok := s.store.GetSecret(ns, name)
	if !ok || !t.Allows(ns) {
		apiError(w, http.StatusNotFound, "no secret "+ns+"/"+name)
		return store.Secret{}, false
	}
	return sec, true
}

func (s *Server) apiWhoami(w http.ResponseWriter, r *http.Request, t store.Token) {
	writeJSON(w, http.StatusOK, map[string]any{"name": t.Name, "namespaces": t.Namespaces, "write": t.Write})
}

func (s *Server) apiList(w http.ResponseWriter, r *http.Request, t store.Token) {
	q := r.URL.Query()
	onlyNew, onlyPending, ns := q.Get("new") != "", q.Get("pending") != "", q.Get("namespace")
	out := []APISecret{}
	for _, sec := range s.store.ListSecrets(func(sec *store.Secret) bool {
		return t.Allows(sec.Namespace) &&
			(ns == "" || sec.Namespace == ns) &&
			(!onlyNew || sec.NewFor(t.Name)) &&
			(!onlyPending || sec.Pending)
	}) {
		out = append(out, s.toAPI(sec, t.Name))
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) apiGet(w http.ResponseWriter, r *http.Request, t store.Token) {
	if sec, ok := s.lookup(w, r, t); ok {
		writeJSON(w, http.StatusOK, s.toAPI(sec, t.Name))
	}
}

// apiReveal is the only endpoint that returns a value. It's a POST so
// nothing caches or prefetches it.
func (s *Server) apiReveal(w http.ResponseWriter, r *http.Request, t store.Token) {
	sec, ok := s.lookup(w, r, t)
	if !ok {
		return
	}
	val, variable, err := s.store.Reveal(sec.Namespace, sec.Name, t.Name)
	switch {
	case errors.Is(err, store.ErrNoValue):
		apiError(w, http.StatusConflict, sec.Ref()+" has no value yet")
		return
	case err != nil:
		apiError(w, http.StatusInternalServerError, err.Error())
		return
	}
	kind := "variable"
	if !variable { // variables aren't secret, so their reads aren't logged
		kind = "secret"
		s.event(r, actor(t), "secret.read", sec.Ref(), r.URL.Query().Get("purpose"))
	}
	writeJSON(w, http.StatusOK, map[string]string{"ref": sec.Ref(), "kind": kind, "value": string(val)})
}

func (s *Server) apiAck(w http.ResponseWriter, r *http.Request, t store.Token) {
	sec, ok := s.lookup(w, r, t)
	if !ok {
		return
	}
	if err := s.store.Ack(sec.Namespace, sec.Name, t.Name); err != nil {
		apiError(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.event(r, actor(t), "secret.ack", sec.Ref(), "")
	writeJSON(w, http.StatusOK, map[string]string{"ref": sec.Ref()})
}

type putBody struct {
	Value       string  `json:"value"`
	Description *string `json:"description"`
	Usage       *string `json:"usage"`
	Expires     *string `json:"expires"`
	Variable    bool    `json:"variable"` // omitted means secret, even when replacing a variable
	Overwrite   bool    `json:"overwrite"`
}

// apiPut lets write-enabled agents store a value, e.g. a password they just
// generated for a new service.
func (s *Server) apiPut(w http.ResponseWriter, r *http.Request, t store.Token) {
	ns, name := r.PathValue("ns"), r.PathValue("name")
	if !t.Write || !t.Allows(ns) {
		apiError(w, http.StatusForbidden, "this token can't write to namespace "+ns)
		return
	}
	var b putBody
	if err := json.NewDecoder(r.Body).Decode(&b); err != nil {
		apiError(w, http.StatusBadRequest, "body must be JSON: "+err.Error())
		return
	}
	if b.Value == "" {
		apiError(w, http.StatusBadRequest, "value is empty")
		return
	}
	old, exists := s.store.GetSecret(ns, name)
	conflict := func() {
		apiError(w, http.StatusConflict, ns+"/"+name+" already has a value; set overwrite to replace it")
	}
	if exists && old.HasValue() && !b.Overwrite {
		conflict()
		return
	}
	// The kind is never inherited: a value is a variable only when this
	// request says so, so a generated password written over a variable
	// doesn't become one.
	meta := store.Meta{Description: old.Description, Usage: old.Usage, Expires: old.Expires, Variable: b.Variable}
	if b.Description != nil {
		meta.Description = *b.Description
	}
	if b.Usage != nil {
		meta.Usage = *b.Usage
	}
	if b.Expires != nil {
		exp, err := parseDate(*b.Expires)
		if err != nil {
			apiError(w, http.StatusBadRequest, err.Error())
			return
		}
		meta.Expires = exp
	}
	put := s.store.PutValue
	if !b.Overwrite {
		put = s.store.CreateValue // re-checked under the store's lock
	}
	if err := put(ns, name, []byte(b.Value), &meta); err != nil {
		if errors.Is(err, store.ErrExists) {
			conflict()
			return
		}
		apiError(w, http.StatusBadRequest, err.Error())
		return
	}
	s.event(r, actor(t), "secret.set", ns+"/"+name, "")
	if exists && old.Variable != meta.Variable {
		s.event(r, actor(t), "secret.kind", ns+"/"+name, kindChange(meta.Variable))
	}
	writeJSON(w, http.StatusOK, map[string]string{"ref": ns + "/" + name})
}

type requestBody struct {
	Namespace   string `json:"namespace"`
	Name        string `json:"name"`
	Description string `json:"description"`
	Usage       string `json:"usage"`
}

// apiRequest creates a placeholder for the human to fill in.
func (s *Server) apiRequest(w http.ResponseWriter, r *http.Request, t store.Token) {
	var b requestBody
	if err := json.NewDecoder(r.Body).Decode(&b); err != nil {
		apiError(w, http.StatusBadRequest, "body must be JSON: "+err.Error())
		return
	}
	if b.Namespace == "" && len(t.Namespaces) == 1 {
		b.Namespace = t.Namespaces[0]
	}
	if !t.Allows(b.Namespace) {
		apiError(w, http.StatusForbidden, "this token isn't granted namespace "+b.Namespace)
		return
	}
	err := s.store.Request(b.Namespace, b.Name, strings.TrimSpace(b.Description), strings.TrimSpace(b.Usage), t.Name)
	switch {
	case errors.Is(err, store.ErrExists):
		apiError(w, http.StatusConflict, b.Namespace+"/"+b.Name+" already has a value")
		return
	case errors.Is(err, store.ErrRequestedByOther):
		apiError(w, http.StatusConflict, b.Namespace+"/"+b.Name+" was already requested by another agent; only that agent or the admin can change the request")
		return
	case err != nil:
		apiError(w, http.StatusBadRequest, err.Error())
		return
	}
	u := s.secretURL(b.Namespace, b.Name)
	s.event(r, actor(t), "secret.request", b.Namespace+"/"+b.Name, "")
	writeJSON(w, http.StatusCreated, map[string]string{"ref": b.Namespace + "/" + b.Name, "url": u})
}

// maxExpiringDays bounds ?days= (100 years), so days*24h can't overflow.
const maxExpiringDays = 36500

func (s *Server) apiExpiring(w http.ResponseWriter, r *http.Request, t store.Token) {
	days := 14
	if d, err := strconv.Atoi(r.URL.Query().Get("days")); err == nil && d >= 0 {
		days = min(d, maxExpiringDays) // a huge value would overflow the duration
	}
	cutoff := s.now().Add(time.Duration(days) * 24 * time.Hour)
	out := []APISecret{}
	for _, sec := range s.store.ListSecrets(func(sec *store.Secret) bool {
		return t.Allows(sec.Namespace) && sec.Expires != nil && sec.Expires.Before(cutoff)
	}) {
		out = append(out, s.toAPI(sec, t.Name))
	}
	writeJSON(w, http.StatusOK, out)
}
