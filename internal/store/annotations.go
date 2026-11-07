package store

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/url"
	"slices"
	"sort"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

// What agents can say about a key besides its value: a status, flags for
// the admin, notes, and proposed descriptions. Everything here lives in
// Secret.Ext or state.History, outside the legacy view, so a release from
// before them still starts on the file (see legacyView).

var (
	ErrReadOnly      = errors.New("this token is read-only")
	ErrNotOwner      = errors.New("this token has add permission: it can only replace values it created")
	ErrBadPermission = errors.New("permission must be read, add or write")
	ErrTooLong       = errors.New("text is too long")
	ErrBadText       = errors.New("text has control or invisible formatting characters (such as bidi overrides or zero-width spaces)")
	ErrEmpty         = errors.New("the text is empty")
	ErrBadLink       = errors.New("the link must be an http or https URL")
	ErrBadStatus     = errors.New("status must be ok, expired, revoked, leaked or replaced-by NAME")
	// ErrNoReplacement: replaced-by names a key that isn't in the same
	// namespace (or doesn't exist; the two look the same).
	ErrNoReplacement = errors.New("replaced-by must name another key that exists in the same namespace")
	// ErrAdminStatus: the admin set the status, so only the admin changes it.
	ErrAdminStatus = errors.New("the admin set this key's status; only the admin can change it")
	// ErrChanged: what the admin reviewed was replaced in the meantime.
	ErrChanged = errors.New("the agent changed its proposal while you were reviewing it; review the new one")
	// ErrLimit: too many open flags, pending notes or open requests.
	ErrLimit = errors.New("too many open flags, pending notes or open requests from this token; wait for the admin to deal with them")
)

const (
	// MaxText bounds a note, description or usage.
	MaxText = 2000
	// MaxReason and MaxLink bound a flag.
	MaxReason = 500
	MaxLink   = 500

	// maxHistoryPerNamespace bounds each namespace's history separately,
	// so a token can only ever push out events in namespaces it's granted
	// (see record for which events go first).
	maxHistoryPerNamespace = 500
	// maxFlagsPerToken bounds open flags per live token. There's no
	// overall cap: tokens are made only by the admin, so this bounds the
	// total, and a cap shared by everyone would let a few tokens (or
	// revoked ones) stop all the others from flagging.
	maxFlagsPerToken    = 20
	maxNotesPerToken    = 20 // pending
	maxNotesPerSecret   = 50
	maxRequestsPerToken = 20 // pending
)

// Permission is what a token may do besides read.
type Permission string

const (
	PermRead  Permission = "read"
	PermAdd   Permission = "add"
	PermWrite Permission = "write"
)

// Valid reports whether p is one of the three permissions.
func (p Permission) Valid() bool { return p == PermRead || p == PermAdd || p == PermWrite }

// Permission is the token's permission.
func (t Token) Permission() Permission {
	switch {
	case t.Write:
		return PermWrite
	case t.Add:
		return PermAdd
	}
	return PermRead
}

// SecretExt is the newer per-key data. Its slices and pointers are only
// ever replaced, never written through (see state.clone).
type SecretExt struct {
	// CreatedBy is the token that first set the value (empty: the admin).
	// An add token may replace only values it created.
	CreatedBy string  `json:"created_by,omitempty"`
	Status    *Status `json:"status,omitempty"`
	// Flags are open flags; resolved ones live only in History.
	Flags []Flag `json:"flags,omitempty"`
	// Notes are approved and pending agent notes, oldest first.
	Notes []Note `json:"notes,omitempty"`
	// Proposal is description and usage text from an agent, waiting for
	// the admin. Never shown to other agents.
	Proposal *Proposal `json:"proposal,omitempty"`
	// DescriptionBy names the agent whose proposal became the current
	// description, so it's still marked as agent-written.
	DescriptionBy string `json:"description_by,omitempty"`
}

func (e SecretExt) empty() bool {
	return e.CreatedBy == "" && e.Status == nil && len(e.Flags) == 0 && len(e.Notes) == 0 && e.Proposal == nil && e.DescriptionBy == ""
}

func (e SecretExt) clone() SecretExt {
	e.Flags, e.Notes = slices.Clone(e.Flags), slices.Clone(e.Notes)
	return e
}

// ext returns a copy of the secret's Ext to change and pass to setExt.
func (sec *Secret) ext() SecretExt {
	if sec.Ext == nil {
		return SecretExt{}
	}
	return sec.Ext.clone()
}

// setExt stores e, or nil when it's empty, so a secret with nothing newer
// is stored exactly as an older release stores it.
func (sec *Secret) setExt(e SecretExt) {
	if e.empty() {
		sec.Ext = nil
		return
	}
	sec.Ext = &e
}

func (sec *Secret) creator() string {
	if sec.Ext == nil {
		return ""
	}
	return sec.Ext.CreatedBy
}

// StatusOf returns the key's status, or nil when it's ok.
func (s Secret) StatusOf() *Status {
	if s.Ext == nil {
		return nil
	}
	return s.Ext.Status
}

// Status is a structured marker any token that sees a key can set.
type Status struct {
	Value      string    `json:"value"`                 // expired, revoked, leaked, replaced-by
	ReplacedBy string    `json:"replaced_by,omitempty"` // a key name in the same namespace
	By         string    `json:"by"`                    // "admin" or "token:NAME"
	At         time.Time `json:"at"`
}

// String is "leaked" or "replaced-by NAME".
func (st Status) String() string {
	if st.ReplacedBy != "" {
		return st.Value + " " + st.ReplacedBy
	}
	return st.Value
}

// Flag asks the admin to look at a key. Reason and Link are for the admin
// only; agents see who flagged and when.
type Flag struct {
	ID     string    `json:"id"`
	By     string    `json:"by"` // token name
	At     time.Time `json:"at"`
	Reason string    `json:"reason,omitempty"`
	Link   string    `json:"link,omitempty"`
	// TokenRevoked: the token that raised it was revoked. The flag stays
	// for the admin, but no longer counts as that name's, so a new token
	// given the name isn't blocked or credited with it.
	TokenRevoked bool `json:"token_revoked,omitempty"`
}

// Note is agent-written text about a key. Pending notes are seen only by
// the admin.
type Note struct {
	ID         string     `json:"id"`
	Text       string     `json:"text"`
	By         string     `json:"by"` // token name
	At         time.Time  `json:"at"`
	Pending    bool       `json:"pending,omitempty"`
	ApprovedAt *time.Time `json:"approved_at,omitempty"`
	Edited     bool       `json:"edited,omitempty"` // the admin changed the text before approving
}

// Proposal is description and usage text an agent sent.
type Proposal struct {
	Description string    `json:"description,omitempty"`
	Usage       string    `json:"usage,omitempty"`
	By          string    `json:"by"`
	At          time.Time `json:"at"`
}

// Version identifies this exact proposal. The approve form carries it, so
// an approval applies only to the text the admin saw, not to whatever the
// agent sent in the meantime.
func (p Proposal) Version() string {
	h := sha256.Sum256([]byte(p.By + "\x00" + p.At.UTC().Format(time.RFC3339Nano) + "\x00" + p.Description + "\x00" + p.Usage))
	return hex.EncodeToString(h[:12])
}

// Event is one entry in the change history. Values are never in it.
type Event struct {
	At        time.Time `json:"at"`
	Namespace string    `json:"namespace"`
	Name      string    `json:"name"`
	Action    string    `json:"action"`
	Actor     string    `json:"actor"`            // "admin" or "token:NAME"
	Detail    string    `json:"detail,omitempty"` // shown to agents: a status, a kind
	// Private is shown to the admin only: a flag's reason and link.
	Private string `json:"private,omitempty"`
}

// record appends to the history. Call with s.mu held, before commit.
func (s *Store) record(ev Event) {
	ev.At = s.now().UTC()
	h := append(slices.Clip(s.st.History), ev) // never writes into the snapshot's array
	s.st.History = trimHistory(h, ev.Namespace)
}

// protectedEvent reports whether an event is kept ahead of agents' own
// events: the admin's, and flags (the only record of a flag's reason
// once it's resolved, besides the audit log).
func protectedEvent(ev Event) bool {
	return !strings.HasPrefix(ev.Actor, "token:") || ev.Action == "flagged"
}

// trimHistory brings namespace ns back under maxHistoryPerNamespace. It
// drops the oldest agent event of the token with the most agent events
// in ns, so a token spamming changes only pushes out its own events, and
// never the admin's or flags while any agent event is left. h must not
// share its array with a snapshot.
func trimHistory(h []Event, ns string) []Event {
	for {
		n := 0
		counts := map[string]int{}
		for _, ev := range h {
			if ev.Namespace == ns {
				n++
				if !protectedEvent(ev) {
					counts[ev.Actor]++
				}
			}
		}
		if n <= maxHistoryPerNamespace {
			return h
		}
		heaviest, most := "", 0
		for a, c := range counts {
			if c > most || (c == most && a < heaviest) {
				heaviest, most = a, c
			}
		}
		i := slices.IndexFunc(h, func(ev Event) bool {
			return ev.Namespace == ns && (most == 0 || (!protectedEvent(ev) && ev.Actor == heaviest))
		})
		h = slices.Delete(h, i, i+1)
	}
}

// History returns events newest first, those keep accepts, at most limit
// (0: all).
func (s *Store) History(keep func(Event) bool, limit int) []Event {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []Event
	for i := len(s.st.History) - 1; i >= 0; i-- {
		if ev := s.st.History[i]; keep == nil || keep(ev) {
			out = append(out, ev)
			if limit > 0 && len(out) == limit {
				break
			}
		}
	}
	return out
}

func newID() string {
	b := make([]byte, 6)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return hex.EncodeToString(b)
}

// checkText bounds the length and rejects invalid UTF-8, control
// characters (newlines and tabs are allowed when multiline), and the
// invisible ones that make text read differently from what it is:
// formatting characters (Cf: bidi overrides and isolates, zero-width
// spaces and joiners, the BOM, soft hyphens, tag characters) and the
// Unicode line and paragraph separators.
func checkText(t string, max int, multiline bool) error {
	if len(t) > max {
		return ErrTooLong
	}
	if !utf8.ValidString(t) {
		return ErrBadText
	}
	for _, r := range t {
		if multiline && (r == '\n' || r == '\t') {
			continue
		}
		if unicode.IsControl(r) || unicode.Is(unicode.Cf, r) || unicode.In(r, unicode.Zl, unicode.Zp) {
			return ErrBadText
		}
	}
	return nil
}

// CheckAgentText checks a description (multiline) and usage (one line)
// an agent sends.
func CheckAgentText(description, usage string) error {
	if err := checkText(description, MaxText, true); err != nil {
		return err
	}
	return checkText(usage, MaxText, false)
}

// CheckLink accepts an empty link, or an absolute http(s) URL.
func CheckLink(l string) error {
	if l == "" {
		return nil
	}
	if err := checkText(l, MaxLink, false); err != nil {
		return err
	}
	u, err := url.Parse(l)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || strings.ContainsAny(l, " \"'<>") {
		return ErrBadLink
	}
	return nil
}

// ParseStatus reads "ok", "leaked", "replaced-by NAME" and so on. ok
// returns nil.
func ParseStatus(value, replacedBy string) (*Status, error) {
	switch value {
	case "ok":
		if replacedBy != "" {
			return nil, ErrBadStatus
		}
		return nil, nil
	case "expired", "revoked", "leaked":
		if replacedBy != "" {
			return nil, ErrBadStatus
		}
		return &Status{Value: value}, nil
	case "replaced-by":
		if !ValidSecretName(replacedBy) {
			return nil, ErrBadStatus
		}
		return &Status{Value: value, ReplacedBy: replacedBy}, nil
	}
	return nil, ErrBadStatus
}

// annotate runs f on a copy of the key's Ext under the lock and stores it.
func (s *Store) annotate(ns, name string, f func(sec *Secret, e *SecretExt, now time.Time) error) error {
	_, err := s.annotateBy(ns, name, nil, f)
	return err
}

// AgentCtx says which token is acting, and from where, so a canary it
// touches is logged in the same write.
type AgentCtx struct {
	Token, IP string
}

// annotateBy is annotate for an agent (by set): touching a canary is
// recorded, as action, in the same write.
func (s *Store) annotateBy(ns, name string, by *agentTouch, f func(sec *Secret, e *SecretExt, now time.Time) error) (*CanaryTouch, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	snap := s.st.clone()
	sec, ok := s.st.Secrets[key(ns, name)]
	if !ok {
		return nil, ErrNotFound
	}
	e := sec.ext()
	now := s.now().UTC()
	if err := f(sec, &e, now); err != nil {
		s.st = snap
		return nil, err
	}
	sec.setExt(e)
	var hit *CanaryTouch
	if by != nil && sec.Canary {
		h := s.touchCanary(sec, by.Token, by.IP, by.action, now)
		hit = &h
	}
	return hit, s.commit(snap)
}

type agentTouch struct {
	AgentCtx
	action string
}

// AgentSetStatus is SetStatus by the token in a.
func (s *Store) AgentSetStatus(ns, name, value, replacedBy string, a AgentCtx) (*CanaryTouch, error) {
	return s.setStatus(ns, name, value, replacedBy, "token:"+a.Token, &agentTouch{a, "status"})
}

// AgentAddFlag is AddFlag by the token in a.
func (s *Store) AgentAddFlag(ns, name, reason, link string, a AgentCtx) (*CanaryTouch, error) {
	return s.addFlag(ns, name, a.Token, reason, link, &agentTouch{a, "flag"})
}

// AgentProposeNote is ProposeNote by the token in a.
func (s *Store) AgentProposeNote(ns, name, text string, a AgentCtx) (*CanaryTouch, error) {
	return s.proposeNote(ns, name, a.Token, text, &agentTouch{a, "note"})
}

// SetStatus sets a key's status (value "ok" clears it). actor is "admin"
// or "token:NAME". A token can't change or clear a status the admin set,
// and its replaced-by must name a key in the same namespace.
func (s *Store) SetStatus(ns, name, value, replacedBy, actor string) error {
	_, err := s.setStatus(ns, name, value, replacedBy, actor, nil)
	return err
}

func (s *Store) setStatus(ns, name, value, replacedBy, actor string, by *agentTouch) (*CanaryTouch, error) {
	st, err := ParseStatus(value, replacedBy)
	if err != nil {
		return nil, err
	}
	return s.annotateBy(ns, name, by, func(sec *Secret, e *SecretExt, now time.Time) error {
		if actor != "admin" && e.Status != nil && e.Status.By == "admin" {
			return ErrAdminStatus
		}
		// Same namespace, so a token sees it if it exists: refusing a
		// missing name says nothing about other namespaces.
		if st != nil && st.ReplacedBy != "" {
			if _, ok := s.st.Secrets[key(ns, st.ReplacedBy)]; !ok || st.ReplacedBy == name {
				return ErrNoReplacement
			}
		}
		detail := "ok"
		if st != nil {
			st.By, st.At = actor, now
			detail = st.String()
		}
		e.Status = st
		s.record(Event{Namespace: ns, Name: name, Action: "status", Actor: actor, Detail: detail})
		return nil
	})
}

// AddFlag raises a flag for the admin. A token has at most one open flag
// per key, and maxFlagsPerToken in all. Flags left by a revoked token of
// the same name don't count.
func (s *Store) AddFlag(ns, name, by, reason, link string) error {
	_, err := s.addFlag(ns, name, by, reason, link, nil)
	return err
}

func (s *Store) addFlag(ns, name, by, reason, link string, a *agentTouch) (*CanaryTouch, error) {
	reason = strings.TrimSpace(reason)
	link = strings.TrimSpace(link)
	if err := checkText(reason, MaxReason, false); err != nil {
		return nil, err
	}
	if err := CheckLink(link); err != nil {
		return nil, err
	}
	return s.annotateBy(ns, name, a, func(sec *Secret, e *SecretExt, now time.Time) error {
		mine := 0
		for _, other := range s.st.Secrets {
			if other.Ext == nil {
				continue
			}
			for _, f := range other.Ext.Flags {
				if f.By == by && !f.TokenRevoked {
					mine++
					if other == sec {
						return ErrExists
					}
				}
			}
		}
		if mine >= maxFlagsPerToken {
			return ErrLimit
		}
		e.Flags = append(e.Flags, Flag{ID: newID(), By: by, At: now, Reason: reason, Link: link})
		private := reason
		if link != "" {
			private += " (" + link + ")"
		}
		s.record(Event{Namespace: ns, Name: name, Action: "flagged", Actor: "token:" + by, Private: private})
		return nil
	})
}

// ResolveFlag closes a flag (admin only). It stays in the history.
func (s *Store) ResolveFlag(ns, name, id string) error {
	return s.annotate(ns, name, func(sec *Secret, e *SecretExt, now time.Time) error {
		i := slices.IndexFunc(e.Flags, func(f Flag) bool { return f.ID == id })
		if i < 0 {
			return ErrNotFound
		}
		f := e.Flags[i]
		e.Flags = slices.Delete(e.Flags, i, i+1)
		s.record(Event{Namespace: ns, Name: name, Action: "flag resolved", Actor: "admin", Detail: "flag by " + f.By})
		return nil
	})
}

// ProposeNote adds a pending note. A token has at most one pending note
// per key.
func (s *Store) ProposeNote(ns, name, by, text string) error {
	_, err := s.proposeNote(ns, name, by, text, nil)
	return err
}

func (s *Store) proposeNote(ns, name, by, text string, a *agentTouch) (*CanaryTouch, error) {
	text = strings.TrimSpace(text)
	if text == "" {
		return nil, ErrEmpty
	}
	if err := checkText(text, MaxText, true); err != nil {
		return nil, err
	}
	return s.annotateBy(ns, name, a, func(sec *Secret, e *SecretExt, now time.Time) error {
		mine := 0
		for _, other := range s.st.Secrets {
			if other.Ext == nil {
				continue
			}
			for _, n := range other.Ext.Notes {
				if n.Pending && n.By == by {
					mine++
					if other == sec {
						return ErrExists
					}
				}
			}
		}
		if mine >= maxNotesPerToken || len(e.Notes) >= maxNotesPerSecret {
			return ErrLimit
		}
		e.Notes = append(e.Notes, Note{ID: newID(), Text: text, By: by, At: now, Pending: true})
		return nil
	})
}

// ApproveNote approves a pending note with text, the note as the admin
// left it (edited or not). Empty text is refused: approving should never
// fall back to text the admin cleared.
func (s *Store) ApproveNote(ns, name, id, text string) error {
	text = strings.ReplaceAll(strings.TrimSpace(text), "\r\n", "\n")
	if text == "" {
		return ErrEmpty
	}
	if err := checkText(text, MaxText, true); err != nil {
		return err
	}
	return s.annotate(ns, name, func(sec *Secret, e *SecretExt, now time.Time) error {
		i := slices.IndexFunc(e.Notes, func(n Note) bool { return n.ID == id && n.Pending })
		if i < 0 {
			return ErrNotFound
		}
		n := &e.Notes[i] // e.Notes is a clone
		if text != n.Text {
			n.Text, n.Edited = text, true
		}
		n.Pending, n.ApprovedAt = false, &now
		s.record(Event{Namespace: ns, Name: name, Action: "note approved", Actor: "admin", Detail: "note by " + n.By})
		return nil
	})
}

// RemoveNote rejects a pending note or deletes an approved one.
func (s *Store) RemoveNote(ns, name, id string) error {
	return s.annotate(ns, name, func(sec *Secret, e *SecretExt, now time.Time) error {
		i := slices.IndexFunc(e.Notes, func(n Note) bool { return n.ID == id })
		if i < 0 {
			return ErrNotFound
		}
		n := e.Notes[i]
		e.Notes = slices.Delete(e.Notes, i, i+1)
		if !n.Pending {
			s.record(Event{Namespace: ns, Name: name, Action: "note removed", Actor: "admin", Detail: "note by " + n.By})
		}
		return nil
	})
}

// ApproveProposal makes an agent's proposed description and usage the
// key's own, with the admin's edits. version is the Version of the
// proposal the admin reviewed; if the agent has replaced it since, it's
// ErrChanged and nothing changes.
func (s *Store) ApproveProposal(ns, name, version, description, usage string) error {
	description, usage = strings.TrimSpace(description), strings.TrimSpace(usage)
	return s.annotate(ns, name, func(sec *Secret, e *SecretExt, now time.Time) error {
		if e.Proposal == nil {
			return ErrNotFound
		}
		if e.Proposal.Version() != version {
			return ErrChanged
		}
		sec.Description, sec.Usage = description, usage
		e.DescriptionBy, e.Proposal = e.Proposal.By, nil
		s.record(Event{Namespace: ns, Name: name, Action: "description approved", Actor: "admin", Detail: "proposed by " + e.DescriptionBy})
		return nil
	})
}

// RejectProposal drops an agent's proposed description and usage, if
// it's still the version the admin saw.
func (s *Store) RejectProposal(ns, name, version string) error {
	return s.annotate(ns, name, func(sec *Secret, e *SecretExt, now time.Time) error {
		if e.Proposal == nil {
			return ErrNotFound
		}
		if e.Proposal.Version() != version {
			return ErrChanged
		}
		e.Proposal = nil
		return nil
	})
}

// SetTokenPermission changes what a token may do.
func (s *Store) SetTokenPermission(name string, perm Permission) error {
	if !perm.Valid() {
		return ErrBadPermission
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	snap := s.st.clone()
	t, ok := s.st.Tokens[name]
	if !ok {
		return ErrNotFound
	}
	t.Write, t.Add = perm == PermWrite, perm == PermAdd
	return s.commit(snap)
}

// Attention is a key with something waiting for the admin.
type Attention struct {
	Secret
	Flags    []Flag
	Notes    []Note // pending only
	Proposal *Proposal
}

// NeedsAttention lists keys with open flags, pending notes or a pending
// proposal, sorted by ref.
func (s *Store) NeedsAttention() []Attention {
	var out []Attention
	for _, sec := range s.ListSecrets(func(sec *Secret) bool { return sec.Ext != nil }) {
		a := Attention{Secret: sec, Flags: sec.Ext.Flags, Proposal: sec.Ext.Proposal}
		for _, n := range sec.Ext.Notes {
			if n.Pending {
				a.Notes = append(a.Notes, n)
			}
		}
		if len(a.Flags) > 0 || len(a.Notes) > 0 || a.Proposal != nil {
			out = append(out, a)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Ref() < out[j].Ref() })
	return out
}
