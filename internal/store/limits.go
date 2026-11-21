package store

import (
	"errors"
	"slices"
	"sort"
)

// Per-key limits: the admin can say that only some of the tokens granted
// a key's namespace may use it. A limit restricts use, not visibility: a
// token that has the namespace but isn't listed still sees the key in
// lists, info and history, but can't read its value, replace it or ack
// it. Limits are for secrets only (a variable's value is in every list).
//
// Secret.Limit is outside v6View, under MAC7. It restricts access, so it
// must not be strippable: the first time a limit is written the key check
// becomes keyCheckV7 (MAC7 required, and MAC4 as for keyCheckV4), and only
// DowngradeV7 takes it back. The release with MAC6 (v0.1.3) doesn't know
// keyCheckV7 and refuses the file until that's run.

var (
	// ErrLimited: the key is limited to other tokens. Same answer for a
	// canary as for any other key.
	ErrLimited = errors.New("this key is limited to other agents")
	// ErrLimitVariable: a limited key can't become a variable, and a
	// variable can't be limited.
	ErrLimitVariable = errors.New("a key limited to some agents can only hold a secret, not a variable: keep it a secret, or allow any agent with the namespace on it first")
	// ErrLimitToken: a token to allow doesn't exist or doesn't have the
	// key's namespace.
	ErrLimitToken = errors.New("only agents that have the key's namespace can be allowed on it")
)

// UseLimit lists the tokens, by name, that may use a key. A non-nil
// UseLimit with no tokens means no agent may: never everyone. Never
// written through: replaced whole on every change.
type UseLimit struct {
	Tokens []string `json:"tokens"`
}

// UsableBy reports whether the token named tok may read, replace or ack
// the key: there's no limit, or tok is on it.
func (s Secret) UsableBy(tok string) bool {
	return s.Limit == nil || slices.Contains(s.Limit.Tokens, tok)
}

// SetLimit limits a key to the tokens named (only true), or lifts the
// limit (only false; tokens ignored). Each token must exist and have the
// key's namespace. Like SetCanary it records no history and leaves
// UpdatedAt alone: the audit log has it.
func (s *Store) SetLimit(ns, name string, only bool, tokens []string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	snap := s.st.clone()
	sec, ok := s.st.Secrets[key(ns, name)]
	if !ok {
		return ErrNotFound
	}
	if !only {
		if sec.Limit == nil {
			return nil
		}
		sec.Limit = nil
		return s.commit(snap)
	}
	if sec.Variable {
		return ErrLimitVariable
	}
	list := []string{}
	for _, tok := range tokens {
		if t, ok := s.st.Tokens[tok]; !ok || !t.Allows(ns) {
			return ErrLimitToken
		}
		if !slices.Contains(list, tok) {
			list = append(list, tok)
		}
	}
	sort.Strings(list)
	sec.Limit = &UseLimit{Tokens: list}
	return s.commit(snap)
}

// dropFromLimits takes tok off the limits of the keys in the namespaces
// drop says. A limit left empty stays: no agent, never everyone. Call
// with s.mu held.
func (s *Store) dropFromLimits(tok string, drop func(ns string) bool) {
	for _, sec := range s.st.Secrets {
		if sec.Limit != nil && drop(sec.Namespace) && slices.Contains(sec.Limit.Tokens, tok) {
			sec.Limit = &UseLimit{Tokens: slices.DeleteFunc(slices.Clone(sec.Limit.Tokens), func(n string) bool { return n == tok })}
		}
	}
}

// limitVariable refuses an entry that's both limited and a variable.
func (sec *Secret) limitVariable() error {
	if sec.Limit != nil && sec.Variable {
		return ErrLimitVariable
	}
	return nil
}

func (st *state) hasLimits() bool {
	for _, v := range st.Secrets {
		if v.Limit != nil {
			return true
		}
	}
	return false
}

// FormatV7 reports whether the key check requires MAC7: a key has been
// limited, and the release before limits refuses the file until
// DowngradeV7 is run.
func (s *Store) FormatV7() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.v7 || s.st.hasLimits()
}

// DowngradeV7 rewrites the state so the release before limits (v0.1.3)
// can read it: every key's limit is removed, so each of those keys is
// usable again by every token with its namespace, and the key check goes
// back to keyCheckV4. It returns the keys that were limited, sorted; on a
// file that never had a limit it does nothing.
func (s *Store) DowngradeV7() ([]string, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.v7 && !s.st.hasLimits() {
		return nil, false, nil
	}
	snap := s.st.clone()
	var keys []string
	for k, sec := range s.st.Secrets {
		if sec.Limit != nil {
			sec.Limit = nil
			keys = append(keys, k)
		}
	}
	sort.Strings(keys)
	// keyCheckV4, whatever the file holds: v7 implied it, and v4 never
	// protects less. downgrade-data run again goes on from there.
	oldCheck, oldV4, oldV7 := s.st.KeyCheck, s.v4, s.v7
	s.st.KeyCheck = s.seal([]byte(keyCheckV4), "keycheck")
	s.v4, s.v7 = true, false
	if err := s.commit(snap); err != nil {
		s.st.KeyCheck, s.v4, s.v7 = oldCheck, oldV4, oldV7
		return nil, false, err
	}
	return keys, true, nil
}
