package store

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"slices"
	"time"
)

// Version history: a key keeps up to MaxVersions older values, so two bad
// saves in a row don't lose the last good one. Only the admin sees the
// list (never the values: to see one, restore it and press Show value)
// and restores from it; nothing an agent sees changes.
//
// Previous stays the newest older value, written and rolled back exactly
// as the release with MAC6 (v0.1.3) does. Versions describes it and holds
// the ones older than it. Versions is outside v6View, under MAC7, so that
// release opens the file and drops Versions when it writes it, and it
// writes the whole file every time, so Versions can never be left
// describing a Previous it changed: what's left is the current value and
// Previous as it left them, and history builds up again from there.
// History grants and restricts nothing, so like notify it isn't tied to
// the key check: deleting versions together with MAC7 loses only the
// history. MAC7 stops anyone without the master key editing it.

// MaxVersions is how many older values a key keeps, Previous included.
const MaxVersions = 5

// ErrNoVersion: the older value asked for isn't in the key's history (any
// more). Versions are addressed by ID, never by place, so a page that's
// out of date can't restore a different one.
var ErrNoVersion = errors.New("that older value isn't kept any more (the page was out of date); nothing was changed. Reload the page and try again")

// ValueHistory is a key's history beyond the current value.
type ValueHistory struct {
	// By saved the current value: "admin" or "token:NAME", "" if unknown.
	By string `json:"by,omitempty"`
	// Previous describes Secret.Previous, whose own value and kind stay
	// where the older releases keep them.
	Previous VersionInfo `json:"previous,omitzero"`
	// Older are the values before Previous, newest first. Each is sealed
	// with the AAD field "version:ID", so none can be moved to another
	// slot or key, and the list can shift without resealing.
	Older []Version `json:"older,omitempty"`
}

// VersionInfo is what's known about an older value.
type VersionInfo struct {
	ID         string    `json:"id"`
	ReplacedAt time.Time `json:"replaced_at,omitzero"`
	By         string    `json:"by,omitempty"` // who saved it
}

// Version is an older value before Previous.
type Version struct {
	VersionInfo
	Variable bool   `json:"variable,omitempty"` // its own kind, like PreviousVariable
	Value    []byte `json:"value"`
}

// VersionRow is an older value as the admin's page lists it: no value.
type VersionRow struct {
	VersionInfo
	Age      int // 1 is the newest
	Variable bool
}

// Kind is "variable" or "secret", for display.
func (v VersionRow) Kind() string { return Secret{Variable: v.Variable}.Kind() }

// older is an older value wherever it's kept; field is its AAD field.
type older struct {
	Version
	field string
}

// olderValues lists sec's older values, newest first.
func (sec *Secret) olderValues() []older {
	var h ValueHistory
	if sec.Versions != nil {
		h = *sec.Versions
	}
	var out []older
	if len(sec.Previous) > 0 {
		p := older{Version{h.Previous, sec.PreviousVariable, sec.Previous}, "previous"}
		if p.ID == "" {
			// Written by an older release: an ID that stays while the
			// ciphertext does.
			sum := sha256.Sum256(sec.Previous)
			p.ID = hex.EncodeToString(sum[:8])
		}
		out = append(out, p)
	}
	for _, v := range h.Older {
		out = append(out, older{v, "version:" + v.ID})
	}
	return out
}

func (sec *Secret) olderBytes() int {
	n := 0
	if sec.Versions != nil {
		for _, v := range sec.Versions.Older {
			n += len(v.Value)
		}
	}
	return n
}

func newVersionID() string {
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return hex.EncodeToString(b)
}

// setOlder stores list (newest first, cut to MaxVersions) as sec's older
// values: the first in Previous, the rest in Versions, each resealed only
// if it moves to another field. by saved the current value. It replaces
// Versions rather than writing through it, which clone relies on. On error
// sec is half changed: the caller restores its snapshot.
func (s *Store) setOlder(sec *Secret, list []older, by string) error {
	h := ValueHistory{By: by}
	sec.Previous, sec.PreviousVariable = nil, false
	for i, o := range list[:min(len(list), MaxVersions)] {
		to := "previous"
		if i > 0 {
			to = "version:" + o.ID
		}
		if o.field != to {
			ct, err := s.reseal(o.Value, sec.Namespace, sec.Name, o.field, to)
			if err != nil {
				return err
			}
			o.Value = ct
		}
		if i == 0 {
			sec.Previous, sec.PreviousVariable, h.Previous = o.Value, o.Variable, o.VersionInfo
		} else {
			h.Older = append(h.Older, o.Version)
		}
	}
	sec.Versions = &h
	return nil
}

// withCurrent is list with sec's current value, if it has one, in front:
// replaced now, saved by whoever saved it. Call with s.mu held.
func (s *Store) withCurrent(sec *Secret, list []older, now time.Time) []older {
	if len(sec.Value) == 0 {
		return list
	}
	cur := older{Version{VersionInfo{newVersionID(), now, s.savedBy(sec)}, sec.Variable, sec.Value}, "value"}
	return append([]older{cur}, list...)
}

// savedBy names who saved sec's current value, or "" if that isn't known.
// Until a key has history that's not recorded, so the latest change in the
// history log says, unless it was a rollback or has aged out. Call with
// s.mu held.
func (s *Store) savedBy(sec *Secret) string {
	if sec.Versions != nil {
		return sec.Versions.By
	}
	for i := len(s.st.History) - 1; i >= 0; i-- {
		if ev := s.st.History[i]; ev.Namespace == sec.Namespace && ev.Name == sec.Name {
			switch ev.Action {
			case "created", "replaced":
				return ev.Actor
			case "rolled back", "deleted":
				return ""
			}
		}
	}
	return ""
}

// Versions lists a key's older values, newest first. Never the values.
func (s *Store) Versions(ns, name string) []VersionRow {
	s.mu.Lock()
	defer s.mu.Unlock()
	sec, ok := s.st.Secrets[key(ns, name)]
	if !ok {
		return nil
	}
	var rows []VersionRow
	for i, o := range sec.olderValues() {
		rows = append(rows, VersionRow{o.VersionInfo, i + 1, o.Variable})
	}
	return rows
}

// Rollback restores the newest older value (see Restore).
func (s *Store) Rollback(ns, name string) error {
	_, _, err := s.Restore(ns, name, "")
	return err
}

// Restore makes the older value with this ID the current one; "" is the
// newest. The value it replaces goes to the front of the history, as on
// any save, so a restore loses nothing. It returns what it restored and
// how many older values there were. The change log says "rolled back"
// whichever it was, so agents can't tell one from another.
func (s *Store) Restore(ns, name, id string) (VersionRow, int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	snap := s.st.clone()
	sec, ok := s.st.Secrets[key(ns, name)]
	if !ok {
		return VersionRow{}, 0, ErrNotFound
	}
	list := sec.olderValues()
	i := 0
	if id != "" {
		i = slices.IndexFunc(list, func(o older) bool { return o.ID == id })
	}
	switch {
	case len(list) == 0 && id == "":
		return VersionRow{}, 0, ErrNoPrevious
	case i < 0 || i >= len(list):
		return VersionRow{}, len(list), ErrNoVersion
	}
	o := list[i]
	val, err := s.reseal(o.Value, ns, name, o.field, "value")
	if err != nil {
		return VersionRow{}, len(list), err
	}
	now := s.now().UTC()
	rest := s.withCurrent(sec, slices.Delete(slices.Clone(list), i, i+1), now)
	if err := s.setOlder(sec, rest, o.By); err != nil {
		s.st = snap
		return VersionRow{}, len(list), err
	}
	sec.Value, sec.Variable = val, o.Variable
	if err := sec.limitVariable(); err != nil {
		s.st = snap
		return VersionRow{}, len(list), err
	}
	sec.dropCanaryIfVariable()
	sec.New, sec.AckedBy, sec.UpdatedAt = true, nil, now
	s.record(Event{Namespace: ns, Name: name, Action: "rolled back", Actor: "admin", Detail: sec.Kind()})
	return VersionRow{o.VersionInfo, i + 1, o.Variable}, len(list), s.commit(snap)
}
