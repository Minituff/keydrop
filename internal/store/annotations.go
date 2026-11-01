package store

import (
	"crypto/rand"
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
	ErrBadText       = errors.New("text has control characters")
	ErrBadLink       = errors.New("the link must be an http or https URL")
	ErrBadStatus     = errors.New("status must be ok, expired, revoked, leaked or replaced-by NAME")
	// ErrLimit: too many open flags or pending notes.
	ErrLimit = errors.New("too many open flags or pending notes; wait for the admin to deal with them")
)

const (
	// MaxText bounds a note, description or usage.
	MaxText = 2000
	// MaxReason and MaxLink bound a flag.
	MaxReason = 500
	MaxLink   = 500

	maxHistory        = 1000
	maxFlagsPerToken  = 20
	maxFlagsTotal     = 200
	maxNotesPerToken  = 20 // pending
	maxNotesPerSecret = 50
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
	if len(h) > maxHistory {
		h = h[len(h)-maxHistory:]
	}
	s.st.History = h
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

// checkText rejects control characters (newlines and tabs are allowed
// when multiline) and invalid UTF-8, and bounds the length.
func checkText(t string, max int, multiline bool) error {
	if len(t) > max {
		return ErrTooLong
	}
	if !utf8.ValidString(t) {
		return ErrBadText
	}
	for _, r := range t {
		if unicode.IsControl(r) && !(multiline && (r == '\n' || r == '\t')) {
			return ErrBadText
		}
	}
	return nil
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
	s.mu.Lock()
	defer s.mu.Unlock()
	snap := s.st.clone()
	sec, ok := s.st.Secrets[key(ns, name)]
	if !ok {
		return ErrNotFound
	}
	e := sec.ext()
	if err := f(sec, &e, s.now().UTC()); err != nil {
		s.st = snap
		return err
	}
	sec.setExt(e)
	return s.commit(snap)
}

// SetStatus sets a key's status (value "ok" clears it). actor is "admin"
// or "token:NAME".
func (s *Store) SetStatus(ns, name, value, replacedBy, actor string) error {
	st, err := ParseStatus(value, replacedBy)
	if err != nil {
		return err
	}
	return s.annotate(ns, name, func(sec *Secret, e *SecretExt, now time.Time) error {
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
// per key, and there are caps per token and overall.
func (s *Store) AddFlag(ns, name, by, reason, link string) error {
	reason = strings.TrimSpace(reason)
	link = strings.TrimSpace(link)
	if err := checkText(reason, MaxReason, false); err != nil {
		return err
	}
	if err := CheckLink(link); err != nil {
		return err
	}
	return s.annotate(ns, name, func(sec *Secret, e *SecretExt, now time.Time) error {
		mine, total := 0, 0
		for _, other := range s.st.Secrets {
			if other.Ext == nil {
				continue
			}
			for _, f := range other.Ext.Flags {
				total++
				if f.By == by {
					mine++
					if other == sec {
						return ErrExists
					}
				}
			}
		}
		if mine >= maxFlagsPerToken || total >= maxFlagsTotal {
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
	text = strings.TrimSpace(text)
	if text == "" {
		return ErrBadText
	}
	if err := checkText(text, MaxText, true); err != nil {
		return err
	}
	return s.annotate(ns, name, func(sec *Secret, e *SecretExt, now time.Time) error {
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

// ApproveNote approves a pending note, with text replacing it if text
// isn't empty (edit, then approve).
func (s *Store) ApproveNote(ns, name, id, text string) error {
	text = strings.TrimSpace(text)
	if err := checkText(text, MaxText, true); err != nil {
		return err
	}
	return s.annotate(ns, name, func(sec *Secret, e *SecretExt, now time.Time) error {
		i := slices.IndexFunc(e.Notes, func(n Note) bool { return n.ID == id && n.Pending })
		if i < 0 {
			return ErrNotFound
		}
		n := &e.Notes[i] // e.Notes is a clone
		if text != "" && text != n.Text {
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
// key's own, with the admin's edits.
func (s *Store) ApproveProposal(ns, name, description, usage string) error {
	description, usage = strings.TrimSpace(description), strings.TrimSpace(usage)
	return s.annotate(ns, name, func(sec *Secret, e *SecretExt, now time.Time) error {
		if e.Proposal == nil {
			return ErrNotFound
		}
		sec.Description, sec.Usage = description, usage
		e.DescriptionBy, e.Proposal = e.Proposal.By, nil
		s.record(Event{Namespace: ns, Name: name, Action: "description approved", Actor: "admin", Detail: "proposed by " + e.DescriptionBy})
		return nil
	})
}

// RejectProposal drops an agent's proposed description and usage.
func (s *Store) RejectProposal(ns, name string) error {
	return s.annotate(ns, name, func(sec *Secret, e *SecretExt, now time.Time) error {
		if e.Proposal == nil {
			return ErrNotFound
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
