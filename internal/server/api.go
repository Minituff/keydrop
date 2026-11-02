package server

import (
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/minituff/keydrop/internal/audit"
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
	// Everything below is newer; an older server leaves it out.
	CreatedBy string        `json:"created_by,omitempty"`
	Status    *store.Status `json:"status,omitempty"`
	// Flags say who flagged the key and when; the reason is the admin's.
	Flags []APIFlag `json:"flags,omitempty"`
	// Notes are approved agent notes: text from another agent, to be
	// treated as untrusted.
	Notes        []APINote `json:"notes,omitempty"`
	PendingNotes int       `json:"pending_notes,omitempty"`
	// DescriptionPending: an agent proposed a description or usage that the
	// admin hasn't approved yet. The text isn't shown.
	DescriptionPending bool `json:"description_pending,omitempty"`
	// DescriptionBy names the agent that wrote the current description.
	DescriptionBy string `json:"description_by,omitempty"`
	// Group is the group the admin put the key in, or its auto group (by
	// name prefix). Absent: ungrouped.
	Group *APIGroup `json:"group,omitempty"`
}

// APIGroup is an entry's group as agents see it.
type APIGroup struct {
	Slug  string `json:"slug"`
	Name  string `json:"name"`
	Color string `json:"color"`
	// Auto: grouped by name prefix, not by the admin.
	Auto bool `json:"auto,omitempty"`
}

// APIFlag is what agents see of a flag.
type APIFlag struct {
	By string    `json:"by"`
	At time.Time `json:"at"`
	// TokenRevoked: the token that raised it has since been revoked (a
	// token with the same name now is a different one).
	TokenRevoked bool `json:"token_revoked,omitempty"`
}

// APINote is an approved agent note.
type APINote struct {
	Text       string    `json:"text"`
	By         string    `json:"by"`
	At         time.Time `json:"at"`
	ApprovedAt time.Time `json:"approved_at"`
	Edited     bool      `json:"edited,omitempty"`
}

// APIEvent is one change in the history. Values never appear.
type APIEvent struct {
	At        time.Time `json:"at"`
	Ref       string    `json:"ref"`
	Namespace string    `json:"namespace"`
	Name      string    `json:"name"`
	Action    string    `json:"action"`
	Actor     string    `json:"actor"`
	Detail    string    `json:"detail,omitempty"`
}

// toAPI shapes a secret for token tok; "new" is relative to that token.
// assign is the store's GroupAssignments, or nil to look it up.
func (s *Server) toAPI(sec store.Secret, tok string, assign map[string]store.GroupRef) APISecret {
	a := APISecret{
		Ref: sec.Ref(), Namespace: sec.Namespace, Name: sec.Name, Kind: sec.Kind(),
		Description: sec.Description, Usage: sec.Usage, Expires: sec.Expires,
		HasValue: sec.HasValue(), Pending: sec.Pending, RequestedBy: sec.RequestedBy,
		New: sec.NewFor(tok), UpdatedAt: sec.UpdatedAt,
	}
	// Only this token's own last read: another token's name, or "never
	// read" (as a canary usually is), isn't this agent's to know.
	if sec.LastReadBy == tok && tok != "" {
		a.LastReadAt, a.LastReadBy = sec.LastReadAt, sec.LastReadBy
	}
	if e := sec.Ext; e != nil {
		a.CreatedBy, a.Status, a.DescriptionBy = e.CreatedBy, e.Status, e.DescriptionBy
		a.DescriptionPending = e.Proposal != nil
		for _, f := range e.Flags {
			a.Flags = append(a.Flags, APIFlag{By: f.By, At: f.At, TokenRevoked: f.TokenRevoked})
		}
		for _, n := range e.Notes {
			if n.Pending {
				a.PendingNotes++
			} else if n.ApprovedAt != nil {
				a.Notes = append(a.Notes, APINote{Text: n.Text, By: n.By, At: n.At, ApprovedAt: *n.ApprovedAt, Edited: n.Edited})
			}
		}
	}
	if assign == nil {
		assign = s.store.GroupAssignments()
	}
	if g, ok := assign[sec.Ref()]; ok && !g.Ungrouped() {
		a.Group = &APIGroup{Slug: g.Slug, Name: g.Name, Color: g.Color, Auto: g.Auto}
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

// agent requires a valid, unexpired bearer token.
func (s *Server) agent(h agentHandler) http.HandlerFunc { return s.agentAuth(h, false) }

// agentRenewal is agent for the renewal endpoints only: it also lets in a
// token that expired less than store.RenewalGrace ago, so the agent can ask
// for it to be extended. Same check, same sources; see LookupTokenForRenewal.
func (s *Server) agentRenewal(h agentHandler) http.HandlerFunc { return s.agentAuth(h, true) }

func (s *Server) agentAuth(h agentHandler, renewal bool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		raw, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
		if !ok {
			apiError(w, http.StatusUnauthorized, "missing bearer token")
			return
		}
		ip := s.clientIP(r)
		lookup := s.store.LookupToken
		if renewal {
			lookup = s.store.LookupTokenForRenewal
		}
		t, err := lookup(strings.TrimSpace(raw), ip)
		switch {
		case errors.Is(err, store.ErrSource):
			s.event(r, actor(t), "token.denied", "", "not an allowed source")
			apiError(w, http.StatusForbidden, "token "+t.Name+" isn't allowed from "+ip+"; if that's expected, the admin can add it under Agents")
			return
		case errors.Is(err, store.ErrExpired):
			// Exactly what an unknown token gets; only the log says more.
			s.noisyEvent(r, actor(t), "token.expired", "", "token expired")
			apiError(w, http.StatusUnauthorized, "invalid token")
			return
		case errors.Is(err, store.ErrRotated):
			s.noisyEvent(r, actor(t), "token.replaced", "", "old token used after its renewal was approved")
			apiError(w, http.StatusUnauthorized, "invalid token")
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
		w.Header().Set(HdrAPILevel, strconv.Itoa(APILevel))
		w.Header().Set(HdrMinCLI, strconv.Itoa(MinCLILevel))
		if cliLevel(r) < MinCLILevel {
			apiError(w, http.StatusUpgradeRequired, tooOldCLI)
			return
		}
		// So the CLI can warn before the token stops working.
		w.Header().Set("X-Keydrop-Token-Expires", expiresHeader(t.ExpiresAt))
		h(w, r, t)
	}
}

func expiresHeader(t *time.Time) string {
	if t == nil {
		return "never"
	}
	return t.UTC().Format(time.RFC3339)
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
	writeJSON(w, http.StatusOK, map[string]any{"name": t.Name, "namespaces": t.Namespaces, "write": t.Write, "permission": t.Permission(), "expires_at": t.ExpiresAt})
}

func (s *Server) apiList(w http.ResponseWriter, r *http.Request, t store.Token) {
	q := r.URL.Query()
	onlyNew, onlyPending, ns := q.Get("new") != "", q.Get("pending") != "", q.Get("namespace")
	out := []APISecret{}
	assign := s.store.GroupAssignments()
	for _, sec := range s.store.ListSecrets(func(sec *store.Secret) bool {
		return t.Allows(sec.Namespace) &&
			(ns == "" || sec.Namespace == ns) &&
			(!onlyNew || sec.NewFor(t.Name)) &&
			(!onlyPending || sec.Pending)
	}) {
		out = append(out, s.toAPI(sec, t.Name, assign))
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) apiGet(w http.ResponseWriter, r *http.Request, t store.Token) {
	if sec, ok := s.lookup(w, r, t); ok {
		writeJSON(w, http.StatusOK, s.toAPI(sec, t.Name, nil))
	}
}

// apiReveal is the only endpoint that returns a value. It's a POST so
// nothing caches or prefetches it.
func (s *Server) apiReveal(w http.ResponseWriter, r *http.Request, t store.Token) {
	sec, ok := s.lookup(w, r, t)
	if !ok {
		return
	}
	// Reading the value is what makes it no longer new to this token.
	val, variable, hit, err := s.store.AgentReveal(sec.Namespace, sec.Name, t.Name, s.clientIP(r))
	switch {
	case errors.Is(err, store.ErrNoValue):
		apiError(w, http.StatusConflict, sec.Ref()+" has no value yet")
		return
	case err != nil:
		apiError(w, http.StatusInternalServerError, err.Error())
		return
	}
	kind := "variable"
	switch {
	case hit != nil:
		// One audit entry either way, so a canary read costs the same.
		s.event(r, actor(t), "secret.read.canary", sec.Ref(), r.URL.Query().Get("purpose"))
		s.canaryTouched(r, *hit)
		if !variable {
			kind = "secret"
		}
	case !variable: // variables aren't secret, so their reads aren't logged
		kind = "secret"
		s.event(r, actor(t), "secret.read", sec.Ref(), r.URL.Query().Get("purpose"))
	}
	out := map[string]any{"ref": sec.Ref(), "kind": kind, "value": string(val)}
	if st := sec.StatusOf(); st != nil {
		out["status"] = st // so `keydrop run` can warn
	}
	writeJSON(w, http.StatusOK, out)
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

// apiPut lets agents with add or write permission store a value, e.g. a
// password they just generated for a new service. Description and usage
// they send are proposals for the admin to approve.
func (s *Server) apiPut(w http.ResponseWriter, r *http.Request, t store.Token) {
	ns, name := r.PathValue("ns"), r.PathValue("name")
	if t.Permission() == store.PermRead || !t.Allows(ns) {
		apiError(w, http.StatusForbidden, "this token can't write to namespace "+ns)
		return
	}
	if !s.writeAllowed(w, t) {
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
	// The kind is never inherited: a value is a variable only when this
	// request says so, so a generated password written over a variable
	// doesn't become one.
	p := store.AgentPut{Token: t, Overwrite: b.Overwrite, Variable: b.Variable, IP: s.clientIP(r)}
	if b.Description != nil {
		d := strings.TrimSpace(*b.Description)
		p.Description = &d
	}
	if b.Usage != nil {
		u := strings.TrimSpace(*b.Usage)
		p.Usage = &u
	}
	if b.Expires != nil {
		exp, err := parseDate(*b.Expires)
		if err != nil {
			apiError(w, http.StatusBadRequest, err.Error())
			return
		}
		p.Expires = &exp
	}
	res, err := s.store.AgentPut(ns, name, []byte(b.Value), p)
	switch {
	case errors.Is(err, store.ErrExists):
		apiError(w, http.StatusConflict, ns+"/"+name+" already has a value; set overwrite to replace it")
		return
	case errors.Is(err, store.ErrNotOwner):
		apiError(w, http.StatusForbidden, ns+"/"+name+" was made by someone else, and this token has add permission: it can only replace values it created")
		return
	case errors.Is(err, store.ErrReadOnly):
		apiError(w, http.StatusForbidden, "this token can't write to namespace "+ns)
		return
	case err != nil:
		apiError(w, http.StatusBadRequest, err.Error())
		return
	}
	s.event(r, actor(t), "secret.set", ns+"/"+name, "")
	if res.Existed && res.WasVariable != b.Variable {
		s.event(r, actor(t), "secret.kind", ns+"/"+name, kindChange(b.Variable))
	}
	if res.Canary != nil {
		s.canaryTouched(r, *res.Canary)
	}
	out := map[string]string{"ref": ns + "/" + name}
	if sec, _ := s.store.GetSecret(ns, name); sec.Ext != nil && sec.Ext.Proposal != nil && sec.Ext.Proposal.By == t.Name && (p.Description != nil || p.Usage != nil) {
		s.event(r, actor(t), "secret.propose", ns+"/"+name, "description")
		out["url"] = s.secretURL(ns, name)
	}
	writeJSON(w, http.StatusOK, out)
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
	if !s.writeAllowed(w, t) {
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
	case errors.Is(err, store.ErrLimit):
		apiError(w, http.StatusTooManyRequests, "this token has too many open requests; wait for the admin to fill some")
		return
	case err != nil:
		apiError(w, http.StatusBadRequest, err.Error())
		return
	}
	u := s.secretURL(b.Namespace, b.Name)
	s.event(r, actor(t), "secret.request", b.Namespace+"/"+b.Name, "")
	if b.Description != "" || b.Usage != "" {
		s.event(r, actor(t), "secret.propose", b.Namespace+"/"+b.Name, "description")
	}
	writeJSON(w, http.StatusCreated, map[string]string{"ref": b.Namespace + "/" + b.Name, "url": u})
}

type batchBody struct {
	Namespace   string   `json:"namespace"`
	Names       []string `json:"names"`
	Group       string   `json:"group"` // a proposed group name: agent text
	Description string   `json:"description"`
	Usage       string   `json:"usage"`
}

// apiRequestBatch requests several keys at once, linked so the admin
// fills them on one card. The group name is only a proposal: the admin
// must tick a box to use it. A batch of N counts as N requests towards
// the rate limit and the open-request cap.
func (s *Server) apiRequestBatch(w http.ResponseWriter, r *http.Request, t store.Token) {
	var b batchBody
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
	if len(b.Names) == 0 || len(b.Names) > store.MaxBatch {
		apiError(w, http.StatusBadRequest, "name 1 to "+strconv.Itoa(store.MaxBatch)+" keys")
		return
	}
	if !s.writesAllowed(w, t, len(b.Names)) {
		return
	}
	desc, usage := strings.TrimSpace(b.Description), strings.TrimSpace(b.Usage)
	id, err := s.store.RequestBatch(b.Namespace, b.Names, desc, usage, b.Group, t.Name)
	switch {
	case errors.Is(err, store.ErrExists):
		apiError(w, http.StatusConflict, err.Error()+"; nothing was requested")
		return
	case errors.Is(err, store.ErrRequestedByOther):
		apiError(w, http.StatusConflict, err.Error()+": only that agent or the admin can change the request; nothing was requested")
		return
	case errors.Is(err, store.ErrLimit):
		apiError(w, http.StatusTooManyRequests, "this token would have too many open requests; wait for the admin to fill some, or ask for fewer")
		return
	case errors.Is(err, store.ErrBatch):
		apiError(w, http.StatusBadRequest, "name 1 to "+strconv.Itoa(store.MaxBatch)+" different keys")
		return
	case err != nil:
		apiError(w, http.StatusBadRequest, err.Error())
		return
	}
	refs := make([]string, 0, len(b.Names))
	urls := map[string]string{}
	for _, n := range b.Names {
		ref := b.Namespace + "/" + n
		refs = append(refs, ref)
		if u := s.secretURL(b.Namespace, n); u != "" {
			urls[ref] = u
		}
		s.event(r, actor(t), "secret.request", ref, "batch of "+strconv.Itoa(len(b.Names)))
		if desc != "" || usage != "" {
			s.event(r, actor(t), "secret.propose", ref, "description")
		}
	}
	if strings.TrimSpace(b.Group) != "" {
		s.event(r, actor(t), "group.propose", refs[0], "a group name for the batch")
	}
	out := map[string]any{"refs": refs, "batch": id}
	if len(urls) > 0 {
		out["urls"] = urls
	}
	if s.cfg.PublicURL != "" {
		out["url"] = strings.TrimRight(s.cfg.PublicURL, "/") + "/inbox#batch-" + id
	}
	writeJSON(w, http.StatusCreated, out)
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
	assign := s.store.GroupAssignments()
	for _, sec := range s.store.ListSecrets(func(sec *store.Secret) bool {
		return t.Allows(sec.Namespace) && sec.Expires != nil && sec.Expires.Before(cutoff)
	}) {
		out = append(out, s.toAPI(sec, t.Name, assign))
	}
	writeJSON(w, http.StatusOK, out)
}

// maxHistoryEvents bounds ?limit=.
const maxHistoryEvents = 1000

// apiHistory lists changes to the keys the token can see, newest first.
// It's read-only: nothing records what a token has seen.
func (s *Server) apiHistory(w http.ResponseWriter, r *http.Request, t store.Token) {
	q := r.URL.Query()
	ns, name := q.Get("namespace"), q.Get("name")
	limit := 50
	if l, err := strconv.Atoi(q.Get("limit")); err == nil && l > 0 {
		limit = min(l, maxHistoryEvents)
	}
	out := []APIEvent{}
	for _, ev := range s.store.History(func(ev store.Event) bool {
		return t.Allows(ev.Namespace) && (ns == "" || ev.Namespace == ns) && (name == "" || ev.Name == name)
	}, limit) {
		// Private (a flag's reason) is the admin's only.
		out = append(out, APIEvent{At: ev.At, Ref: ev.Namespace + "/" + ev.Name, Namespace: ev.Namespace, Name: ev.Name, Action: ev.Action, Actor: ev.Actor, Detail: ev.Detail})
	}
	writeJSON(w, http.StatusOK, out)
}

// annotationError maps the store's errors for flag, status and note to
// responses.
func annotationError(w http.ResponseWriter, sec store.Secret, err error) {
	switch {
	case errors.Is(err, store.ErrNotFound):
		apiError(w, http.StatusNotFound, "no secret "+sec.Ref())
	case errors.Is(err, store.ErrLimit):
		apiError(w, http.StatusTooManyRequests, err.Error())
	case errors.Is(err, store.ErrAdminStatus):
		apiError(w, http.StatusForbidden, err.Error())
	case errors.Is(err, store.ErrTooLong), errors.Is(err, store.ErrBadText), errors.Is(err, store.ErrBadLink), errors.Is(err, store.ErrBadStatus),
		errors.Is(err, store.ErrNoReplacement), errors.Is(err, store.ErrEmpty):
		apiError(w, http.StatusBadRequest, err.Error())
	default:
		apiError(w, http.StatusInternalServerError, err.Error())
	}
}

// annotationTarget does what every flag, status and note call shares: the
// key must be visible to the token (else it doesn't exist), the token
// within its rate limit, and the body JSON.
func (s *Server) annotationTarget(w http.ResponseWriter, r *http.Request, t store.Token, body any) (store.Secret, bool) {
	sec, ok := s.lookup(w, r, t)
	if !ok {
		return sec, false
	}
	if !s.annotations.allow(t.Name, s.now()) {
		apiError(w, http.StatusTooManyRequests, "too many flags, statuses and notes from this token; try again later")
		return sec, false
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 16<<10)).Decode(body); err != nil {
		apiError(w, http.StatusBadRequest, "body must be JSON: "+err.Error())
		return sec, false
	}
	return sec, true
}

type flagBody struct {
	Reason string `json:"reason"`
	Link   string `json:"link"`
}

// apiFlag lets any token that sees a key ask the admin to look at it.
func (s *Server) apiFlag(w http.ResponseWriter, r *http.Request, t store.Token) {
	var b flagBody
	sec, ok := s.annotationTarget(w, r, t, &b)
	if !ok {
		return
	}
	hit, err := s.store.AgentAddFlag(sec.Namespace, sec.Name, b.Reason, b.Link, s.agentCtx(r, t))
	if err != nil {
		if errors.Is(err, store.ErrExists) {
			apiError(w, http.StatusConflict, "this token already has an open flag on "+sec.Ref())
			return
		}
		annotationError(w, sec, err)
		return
	}
	// The reason and link go into the audit log too, so the record of
	// what an agent said survives the flag being resolved.
	text := strings.TrimSpace(b.Reason)
	if l := strings.TrimSpace(b.Link); l != "" {
		text += " <" + l + ">"
	}
	s.audit.Add(audit.Event{Actor: actor(t), Action: "secret.flag", Target: sec.Ref(), Text: text, IP: s.clientIP(r)})
	if hit != nil {
		s.canaryTouched(r, *hit)
	}
	writeJSON(w, http.StatusCreated, map[string]string{"ref": sec.Ref()})
}

type statusBody struct {
	Status     string `json:"status"`
	ReplacedBy string `json:"replaced_by"`
}

// apiStatus sets a key's status; "ok" clears it.
func (s *Server) apiStatus(w http.ResponseWriter, r *http.Request, t store.Token) {
	var b statusBody
	sec, ok := s.annotationTarget(w, r, t, &b)
	if !ok {
		return
	}
	hit, err := s.store.AgentSetStatus(sec.Namespace, sec.Name, b.Status, b.ReplacedBy, s.agentCtx(r, t))
	if err != nil {
		annotationError(w, sec, err)
		return
	}
	st, _ := store.ParseStatus(b.Status, b.ReplacedBy)
	detail := "ok"
	if st != nil {
		detail = st.String()
	}
	s.event(r, actor(t), "secret.status", sec.Ref(), detail)
	if hit != nil {
		s.canaryTouched(r, *hit)
	}
	writeJSON(w, http.StatusOK, map[string]string{"ref": sec.Ref(), "status": detail})
}

type noteBody struct {
	Text string `json:"text"`
}

// apiNote proposes a note. No other agent sees it until the admin
// approves; the response links to the page where that happens.
func (s *Server) apiNote(w http.ResponseWriter, r *http.Request, t store.Token) {
	var b noteBody
	sec, ok := s.annotationTarget(w, r, t, &b)
	if !ok {
		return
	}
	hit, err := s.store.AgentProposeNote(sec.Namespace, sec.Name, b.Text, s.agentCtx(r, t))
	if err != nil {
		if errors.Is(err, store.ErrExists) {
			apiError(w, http.StatusConflict, "this token already has a note on "+sec.Ref()+" waiting for approval")
			return
		}
		annotationError(w, sec, err)
		return
	}
	s.event(r, actor(t), "secret.note", sec.Ref(), "proposed")
	if hit != nil {
		s.canaryTouched(r, *hit)
	}
	writeJSON(w, http.StatusCreated, map[string]string{"ref": sec.Ref(), "url": s.secretURL(sec.Namespace, sec.Name)})
}

// writeAllowed applies the per-token limit on puts and requests, which
// add to the store and its history.
func (s *Server) writeAllowed(w http.ResponseWriter, t store.Token) bool {
	return s.writesAllowed(w, t, 1)
}

// writesAllowed is writeAllowed for n writes at once (a batch request):
// all n fit in the limit, or none is counted.
func (s *Server) writesAllowed(w http.ResponseWriter, t store.Token, n int) bool {
	if s.writes.allowN(t.Name, n, s.now()) {
		return true
	}
	apiError(w, http.StatusTooManyRequests, "too many puts and requests from this token; try again later")
	return false
}

// rateLimit allows each token a number of actions per window.
type rateLimit struct {
	mu     sync.Mutex
	n      int
	window time.Duration
	seen   map[string][]time.Time
}

func newRateLimit(n int, window time.Duration) *rateLimit {
	return &rateLimit{n: n, window: window, seen: map[string][]time.Time{}}
}

func (l *rateLimit) allow(tok string, now time.Time) bool {
	return l.allowN(tok, 1, now)
}

// allowN counts n actions at once, if they all fit.
func (l *rateLimit) allowN(tok string, n int, now time.Time) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	recent := l.seen[tok][:0:0]
	for _, at := range l.seen[tok] {
		if now.Sub(at) < l.window {
			recent = append(recent, at)
		}
	}
	if len(recent)+n > l.n {
		l.seen[tok] = recent
		return false
	}
	for range n {
		recent = append(recent, now)
	}
	l.seen[tok] = recent
	return true
}
