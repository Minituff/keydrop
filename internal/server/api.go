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

func (s *Server) toAPI(sec store.Secret) APISecret {
	a := APISecret{
		Ref: sec.Ref(), Namespace: sec.Namespace, Name: sec.Name, Kind: sec.Kind(),
		Description: sec.Description, Usage: sec.Usage, Expires: sec.Expires,
		HasValue: sec.HasValue(), Pending: sec.Pending, RequestedBy: sec.RequestedBy,
		New: sec.New, UpdatedAt: sec.UpdatedAt, LastReadAt: sec.LastReadAt, LastReadBy: sec.LastReadBy,
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
		t, ok := s.store.LookupToken(strings.TrimSpace(raw))
		if !ok {
			s.event(r, "unknown", "api.badtoken", "", "")
			apiError(w, http.StatusUnauthorized, "invalid token")
			return
		}
		h(w, r, t)
	}
}

func actor(t store.Token) string { return "token:" + t.Name }

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
			(!onlyNew || sec.New) &&
			(!onlyPending || sec.Pending)
	}) {
		out = append(out, s.toAPI(sec))
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) apiGet(w http.ResponseWriter, r *http.Request, t store.Token) {
	if sec, ok := s.lookup(w, r, t); ok {
		writeJSON(w, http.StatusOK, s.toAPI(sec))
	}
}

// apiReveal is the only endpoint that returns a value. It's a POST so
// nothing caches or prefetches it.
func (s *Server) apiReveal(w http.ResponseWriter, r *http.Request, t store.Token) {
	sec, ok := s.lookup(w, r, t)
	if !ok {
		return
	}
	val, err := s.store.Reveal(sec.Namespace, sec.Name, t.Name)
	switch {
	case errors.Is(err, store.ErrNoValue):
		apiError(w, http.StatusConflict, sec.Ref()+" has no value yet")
		return
	case err != nil:
		apiError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if !sec.Variable { // variables aren't secret, so their reads aren't logged
		s.event(r, actor(t), "secret.read", sec.Ref(), r.URL.Query().Get("purpose"))
	}
	writeJSON(w, http.StatusOK, map[string]string{"ref": sec.Ref(), "kind": sec.Kind(), "value": string(val)})
}

func (s *Server) apiAck(w http.ResponseWriter, r *http.Request, t store.Token) {
	sec, ok := s.lookup(w, r, t)
	if !ok {
		return
	}
	if err := s.store.Ack(sec.Namespace, sec.Name); err != nil {
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
	Variable    *bool   `json:"variable"`
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
	if exists && old.HasValue() && !b.Overwrite {
		apiError(w, http.StatusConflict, ns+"/"+name+" already has a value; set overwrite to replace it")
		return
	}
	meta := store.Meta{Description: old.Description, Usage: old.Usage, Expires: old.Expires, Variable: old.Variable}
	if b.Variable != nil {
		meta.Variable = *b.Variable
	}
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
	if err := s.store.PutValue(ns, name, []byte(b.Value), &meta); err != nil {
		apiError(w, http.StatusBadRequest, err.Error())
		return
	}
	s.event(r, actor(t), "secret.set", ns+"/"+name, "")
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
	case err != nil:
		apiError(w, http.StatusBadRequest, err.Error())
		return
	}
	u := s.secretURL(b.Namespace, b.Name)
	s.event(r, actor(t), "secret.request", b.Namespace+"/"+b.Name, "")
	writeJSON(w, http.StatusCreated, map[string]string{"ref": b.Namespace + "/" + b.Name, "url": u})
}

func (s *Server) apiExpiring(w http.ResponseWriter, r *http.Request, t store.Token) {
	days := 14
	if d, err := strconv.Atoi(r.URL.Query().Get("days")); err == nil && d >= 0 {
		days = d
	}
	cutoff := s.now().Add(time.Duration(days) * 24 * time.Hour)
	out := []APISecret{}
	for _, sec := range s.store.ListSecrets(func(sec *store.Secret) bool {
		return t.Allows(sec.Namespace) && sec.Expires != nil && sec.Expires.Before(cutoff)
	}) {
		out = append(out, s.toAPI(sec))
	}
	writeJSON(w, http.StatusOK, out)
}
