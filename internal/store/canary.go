package store

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"maps"
	"slices"
	"sort"
	"time"
)

// Canaries, token expiry and the duplicate-value check. The stored parts
// (state.Canary, Secret.Canary, Token.ExpiresAt) are outside v3View, under
// MAC4, so the release before them still opens a file this one wrote.

var (
	// ErrExpired: the token is past its ExpiresAt. Callers must treat it
	// exactly like an unknown token towards the agent.
	ErrExpired = errors.New("token expired")
	// ErrCanaryVariable: only secrets can be canaries.
	ErrCanaryVariable = errors.New("only secrets can be canaries, not variables")
	// ErrBadLifetime: not one of the lifetimes on offer.
	ErrBadLifetime = errors.New("token lifetime must be 30, 90, 180 or 365 days, or never")
)

// TokenLifetimes are the token lifetimes the admin can pick, in days. 0 is
// never.
var TokenLifetimes = []int{30, 90, 180, 365, 0}

// DefaultTokenLifetime is the lifetime preselected in every form, in days.
const DefaultTokenLifetime = 90

// RenewalGrace is how long after expiring a token may still ask for its
// own renewal (and nothing else). After that only pairing again helps.
const RenewalGrace = 30 * 24 * time.Hour

// CheckLifetime reports whether days is one of TokenLifetimes.
func CheckLifetime(days int) error {
	if !slices.Contains(TokenLifetimes, days) {
		return ErrBadLifetime
	}
	return nil
}

func expiryFor(days int, now time.Time) *time.Time {
	if days == 0 {
		return nil
	}
	t := now.UTC().Add(time.Duration(days) * 24 * time.Hour)
	return &t
}

// Expired reports whether the token is past its expiry at now.
func (t *Token) Expired(now time.Time) bool {
	return t.ExpiresAt != nil && !now.Before(*t.ExpiresAt)
}

// RenewLifetime is the lifetime to offer when renewing: the one it was
// last given, else the default.
func (t *Token) RenewLifetime() int {
	if t.Lifetime > 0 {
		return t.Lifetime
	}
	return DefaultTokenLifetime
}

// RenewalRequest is an agent asking, with its own token, for that token to
// be extended. The admin approves it (with a lifetime) or declines it.
type RenewalRequest struct {
	At time.Time `json:"at"`
	IP string    `json:"ip,omitempty"`
}

// ErrNoExpiry: the token never expires, so there's nothing to renew.
var ErrNoExpiry = errors.New("this token doesn't expire")

// CreateTokenExpiring is CreateToken with a lifetime in days (one of
// TokenLifetimes; 0 is never).
func (s *Store) CreateTokenExpiring(name string, namespaces []string, perm Permission, sources []string, days int) (string, error) {
	if err := CheckLifetime(days); err != nil {
		return "", err
	}
	return s.createToken(name, namespaces, perm, sources, nil, days)
}

// RotationCollectWindow is how long an agent has to collect the token
// that replaces its own after a renewal is approved. After that the old
// token is gone for good, and if it wasn't collected the agent must pair
// again.
const RotationCollectWindow = 7 * 24 * time.Hour

// Rotation is an approved renewal: the token's Hash is already the new
// token's, and the old token, known here only by OldHash, can do nothing
// but collect the new one (and ask where its renewal stands). That way
// round is fail-safe: drop the Rotation and the old token is dead, not
// revived. The new token stays sealed (encrypted under the master key, the
// AAD binding it to the token's name and hash) so collecting can be
// repeated if the agent lost the answer, until the new token is first used
// or CollectBy passes; then the Rotation, and with it the old hash and the
// sealed copy, is deleted.
type Rotation struct {
	OldHash string `json:"old_hash"`
	Sealed  []byte `json:"sealed"` // the new token, encrypted
	// IP is the only address the new token may be collected from: where
	// the renewal was asked from (or, for one the admin started, where the
	// token was last used). Empty: any of the token's allowed sources.
	IP        string     `json:"ip,omitempty"`
	At        time.Time  `json:"at"`
	CollectBy time.Time  `json:"collect_by"`
	Collected *time.Time `json:"collected,omitempty"` // first collected
}

func rotationAAD(name, hash string) string { return "rotation:" + name + ":" + hash }

var (
	// ErrRotated: the token was renewed, and may only collect its
	// replacement. Callers must refuse it like an unknown token everywhere
	// else.
	ErrRotated = errors.New("token replaced by a renewal")
	// ErrCollectIP: a collect from an address other than the one that
	// asked for the renewal. Refused, logged and alerted on.
	ErrCollectIP = errors.New("the renewed token can only be collected from the address that asked for the renewal")
	// ErrCollecting: the new token was collected but not used yet; renewing
	// again now could leave the agent holding neither.
	ErrCollecting = errors.New("the agent has collected its renewed token but not used it yet; renew again once it has")
)

// RotateToken renews a token by replacing it: a new token for the same
// agent (same name, namespaces, permission and sources) with a lifetime of
// days from now (0: never), for the agent to collect within
// RotationCollectWindow. It settles any renewal the agent asked for. From
// now on the old token can only collect the new one (LookupTokenForRenewal,
// CollectRotation). Approving again before it's collected replaces the new
// token, and the old one can still collect.
func (s *Store) RotateToken(name string, days int) (Rotation, error) {
	if err := CheckLifetime(days); err != nil {
		return Rotation{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	snap := s.st.clone()
	t, ok := s.st.Tokens[name]
	if !ok {
		return Rotation{}, ErrNotFound
	}
	now := s.now().UTC()
	rot := Rotation{OldHash: t.Hash, IP: t.LastUsedFrom, At: now, CollectBy: now.Add(RotationCollectWindow)}
	if t.Rotation != nil {
		if t.Rotation.Collected != nil {
			return Rotation{}, ErrCollecting
		}
		rot.OldHash, rot.IP = t.Rotation.OldHash, t.Rotation.IP
	}
	if t.Renewal != nil {
		rot.IP = t.Renewal.IP
	}
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return Rotation{}, err
	}
	plain := TokenPrefix + base64.RawURLEncoding.EncodeToString(b)
	h := hashToken(plain)
	rot.Sealed = s.seal([]byte(plain), rotationAAD(name, h))
	t.Hash, t.ExpiresAt, t.Lifetime, t.Renewal = h, expiryFor(days, now), days, nil
	t.Rotation = &rot
	out := rot
	out.Sealed, out.OldHash = nil, ""
	return out, s.commit(snap)
}

// CollectRotation hands over the new token that replaced old. old is the
// token as LookupTokenForRenewal returned it for the old token (its
// Rotation set); ip is the caller's address, which must be the one the
// renewal was asked from. It can be repeated (the answer may have been
// lost) until the new token is used or the window closes; after that it's
// ErrNotFound.
func (s *Store) CollectRotation(old Token, ip string) (plain string, t Token, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	snap := s.st.clone()
	cur, ok := s.st.Tokens[old.Name]
	if !ok || old.Rotation == nil || cur.Rotation == nil || cur.Rotation.OldHash != old.Rotation.OldHash || !s.now().Before(cur.Rotation.CollectBy) {
		return "", Token{}, ErrNotFound
	}
	rot := cur.Rotation
	if rot.IP != "" && ip != rot.IP {
		return "", *cur, ErrCollectIP
	}
	pt, err := s.open(rot.Sealed, rotationAAD(cur.Name, cur.Hash))
	if err != nil {
		return "", Token{}, fmt.Errorf("decrypting the new token for %s: %w", cur.Name, err)
	}
	if rot.Collected == nil {
		r := *rot
		now := s.now().UTC()
		r.Collected = &now
		cur.Rotation = &r
		if err := s.commit(snap); err != nil {
			return "", Token{}, err
		}
	}
	out := *cur
	out.Rotation = nil
	return string(pt), out, nil
}

// RevokeUncollectedRotations ends the rotations whose collect window has
// passed. A token whose new one was never collected is deleted (nobody
// holds a working token for it) and its name returned; one that was
// collected just loses the old hash.
func (s *Store) RevokeUncollectedRotations(now time.Time) []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	// Like RevokeUncollected: no copy of the state on the polling path.
	if !slices.ContainsFunc(slices.Collect(maps.Values(s.st.Tokens)), func(t *Token) bool {
		return t.Rotation != nil && !now.Before(t.Rotation.CollectBy)
	}) {
		return nil
	}
	snap := s.st.clone()
	var gone []string
	changed := false
	for name, t := range s.st.Tokens {
		if t.Rotation == nil || now.Before(t.Rotation.CollectBy) {
			continue
		}
		changed = true
		if t.Rotation.Collected == nil {
			delete(s.st.Tokens, name)
			gone = append(gone, name)
		} else {
			t.Rotation = nil
		}
	}
	if !changed {
		return nil
	}
	sort.Strings(gone)
	for _, name := range gone {
		s.forgetToken(name)
	}
	if err := s.commit(snap); err != nil {
		return nil
	}
	return gone
}

// SetTokenExpiry sets a token's expiry to exactly at (nil: never), leaving
// its lifetime alone. For tests and maintenance; renewals use RotateToken.
func (s *Store) SetTokenExpiry(name string, at *time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	snap := s.st.clone()
	t, ok := s.st.Tokens[name]
	if !ok {
		return ErrNotFound
	}
	if at != nil {
		e := at.UTC()
		at = &e
	}
	t.ExpiresAt = at
	return s.commit(snap)
}

// RequestRenewal records that the token named name asks to be renewed,
// from ip. There's at most one pending request per token: asking again
// returns the pending one with created false. A token that never expires
// gets ErrNoExpiry.
func (s *Store) RequestRenewal(name, ip string) (req RenewalRequest, created bool, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	snap := s.st.clone()
	t, ok := s.st.Tokens[name]
	switch {
	case !ok:
		return RenewalRequest{}, false, ErrNotFound
	case t.Rotation != nil:
		return RenewalRequest{}, false, ErrRotated
	case t.ExpiresAt == nil:
		return RenewalRequest{}, false, ErrNoExpiry
	case t.Renewal != nil:
		return *t.Renewal, false, nil
	}
	t.Renewal = &RenewalRequest{At: s.now().UTC(), IP: ip}
	return *t.Renewal, true, s.commit(snap)
}

// DeclineRenewal drops a token's pending renewal request; the expiry
// stays as it was.
func (s *Store) DeclineRenewal(name string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	snap := s.st.clone()
	t, ok := s.st.Tokens[name]
	if !ok || t.Renewal == nil {
		return ErrNotFound
	}
	t.Renewal = nil
	return s.commit(snap)
}

// CanaryState holds the canary settings and the reads the admin hasn't
// dismissed yet. Never written through: replaced whole on every change, so
// a snapshot (see clone) stays intact.
type CanaryState struct {
	// RevokeOnRead revokes a token as soon as it reads a canary.
	RevokeOnRead bool        `json:"revoke_on_read,omitempty"`
	Hits         []CanaryHit `json:"hits,omitempty"`
	// Dropped counts touches by (canary, token) pairs that didn't fit
	// (maxCanaryHits): the audit log has them, the Inbox only this count.
	Dropped int `json:"dropped,omitempty"`
}

// CanaryHit is every touch of one canary by one token (a read, or a write,
// status, flag or note), shown in the Inbox until the admin dismisses it.
type CanaryHit struct {
	ID        string    `json:"id"`
	Namespace string    `json:"namespace"`
	Name      string    `json:"name"`
	Token     string    `json:"token"`
	IPs       []string  `json:"ips,omitempty"` // the first maxHitIPs addresses
	First     time.Time `json:"first"`
	Last      time.Time `json:"last"`
	Count     int       `json:"count"`
	Action    string    `json:"action"` // the last touch: read, write, status, flag, note
	// TokenRevoked: a touch revoked the token (RevokeOnRead).
	TokenRevoked bool `json:"token_revoked,omitempty"`
}

// Ref is the "namespace/name" of the canary.
func (h CanaryHit) Ref() string { return key(h.Namespace, h.Name) }

// CanaryTouch is one touch of a canary, for the log and the alert.
type CanaryTouch struct {
	Namespace, Name, Token, IP, Action string
	At                                 time.Time
	TokenRevoked                       bool
}

// Ref is the "namespace/name" of the canary.
func (h CanaryTouch) Ref() string { return key(h.Namespace, h.Name) }

const (
	// maxCanaryHits caps the (canary, token) entries kept. An entry is
	// never evicted for a newer one: past the cap only Dropped counts up.
	maxCanaryHits = 100
	maxHitIPs     = 5
)

func (st *state) canary() CanaryState {
	if st.Canary == nil {
		return CanaryState{}
	}
	c := *st.Canary
	c.Hits = slices.Clone(c.Hits)
	for i := range c.Hits {
		c.Hits[i].IPs = slices.Clone(c.Hits[i].IPs)
	}
	return c
}

// setCanary stores c, or nothing when it's all defaults, so a file with no
// canary settings is exactly what the release before them writes.
func (st *state) setCanary(c CanaryState) {
	if !c.RevokeOnRead && len(c.Hits) == 0 && c.Dropped == 0 {
		st.Canary = nil
		return
	}
	st.Canary = &c
}

// SetCanary marks a secret as a canary, or not. It records no history and
// leaves UpdatedAt alone: agents see the history, and must not be able to
// tell.
func (s *Store) SetCanary(ns, name string, on bool) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	snap := s.st.clone()
	sec, ok := s.st.Secrets[key(ns, name)]
	if !ok {
		return ErrNotFound
	}
	if on && sec.Variable {
		return ErrCanaryVariable
	}
	if sec.Canary == on {
		return nil
	}
	sec.Canary = on
	return s.commit(snap)
}

// RevokeOnCanary reports whether reading a canary revokes the token.
func (s *Store) RevokeOnCanary() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.st.canary().RevokeOnRead
}

// SetRevokeOnCanary turns revoking a token that reads a canary on or off.
func (s *Store) SetRevokeOnCanary(on bool) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	snap := s.st.clone()
	c := s.st.canary()
	c.RevokeOnRead = on
	s.st.setCanary(c)
	return s.commit(snap)
}

// CanaryHits returns the undismissed canary entries, most recently
// touched first, and how many touches didn't fit.
func (s *Store) CanaryHits() ([]CanaryHit, int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	c := s.st.canary()
	slices.SortStableFunc(c.Hits, func(a, b CanaryHit) int { return b.Last.Compare(a.Last) })
	return c.Hits, c.Dropped
}

// DismissCanaryHit removes one entry from the Inbox. "dropped" clears the
// overflow count.
func (s *Store) DismissCanaryHit(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	snap := s.st.clone()
	c := s.st.canary()
	if id == "dropped" && c.Dropped > 0 {
		c.Dropped = 0
	} else {
		i := slices.IndexFunc(c.Hits, func(h CanaryHit) bool { return h.ID == id })
		if i < 0 {
			return ErrNotFound
		}
		c.Hits = slices.Delete(c.Hits, i, i+1)
	}
	s.st.setCanary(c)
	return s.commit(snap)
}

// touchCanary records that token tok did action to sec, a canary, from ip
// and, if that's switched on, revokes tok. Call with s.mu held, before the
// commit of the action itself, so both are one write (touching a canary
// costs the same as touching any other secret).
func (s *Store) touchCanary(sec *Secret, tok, ip, action string, at time.Time) CanaryTouch {
	c := s.st.canary()
	ev := CanaryTouch{Namespace: sec.Namespace, Name: sec.Name, Token: tok, IP: ip, Action: action, At: at}
	if c.RevokeOnRead {
		if _, ok := s.st.Tokens[tok]; ok {
			delete(s.st.Tokens, tok)
			s.forgetToken(tok)
			ev.TokenRevoked = true
		}
	}
	i := slices.IndexFunc(c.Hits, func(h CanaryHit) bool {
		return h.Namespace == sec.Namespace && h.Name == sec.Name && h.Token == tok
	})
	switch {
	case i >= 0:
		h := &c.Hits[i]
		h.Last, h.Action = at, action
		h.Count++
		if ip != "" && !slices.Contains(h.IPs, ip) && len(h.IPs) < maxHitIPs {
			h.IPs = append(h.IPs, ip)
		}
		h.TokenRevoked = h.TokenRevoked || ev.TokenRevoked
	case len(c.Hits) >= maxCanaryHits:
		c.Dropped++
	default:
		id := make([]byte, 8)
		if _, err := rand.Read(id); err != nil {
			panic(err)
		}
		h := CanaryHit{ID: hex.EncodeToString(id), Namespace: sec.Namespace, Name: sec.Name, Token: tok,
			First: at, Last: at, Count: 1, Action: action, TokenRevoked: ev.TokenRevoked}
		if ip != "" {
			h.IPs = []string{ip}
		}
		c.Hits = append(c.Hits, h)
	}
	s.st.setCanary(c)
	return ev
}

// Duplicate is a stored value equal to another one: Ref's value is the
// same as Other's.
type Duplicate struct {
	Ref, Other string
}

// Duplicates compares the current values of refs ("namespace/name") with
// every other stored value, and with each other, and returns the pairs
// that are equal, each pair once. Two variables with the same value aren't
// reported (a shared username is normal); a secret equal to anything is.
// Values are compared in constant time and never leave this function.
func (s *Store) Duplicates(refs []string) ([]Duplicate, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	type val struct {
		ref      string
		variable bool
		pt       []byte
	}
	var all []val
	keys := make([]string, 0, len(s.st.Secrets))
	for k := range s.st.Secrets {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		sec := s.st.Secrets[k]
		if len(sec.Value) == 0 {
			continue
		}
		pt, err := s.open(sec.Value, aad(sec.Namespace, sec.Name, "value"))
		if err != nil {
			return nil, fmt.Errorf("decrypting %s: %w", k, err)
		}
		all = append(all, val{k, sec.Variable, pt})
	}
	defer func() {
		for _, v := range all {
			clear(v.pt)
		}
	}()
	var out []Duplicate
	seen := map[[2]string]bool{}
	for _, ref := range refs {
		i := slices.IndexFunc(all, func(v val) bool { return v.ref == ref })
		if i < 0 {
			continue
		}
		a := all[i]
		for _, b := range all {
			if b.ref == a.ref || (a.variable && b.variable) {
				continue
			}
			pair := [2]string{min(a.ref, b.ref), max(a.ref, b.ref)}
			if seen[pair] || subtle.ConstantTimeCompare(a.pt, b.pt) != 1 {
				continue
			}
			seen[pair] = true
			out = append(out, Duplicate{Ref: a.ref, Other: b.ref})
		}
	}
	return out, nil
}

// FormatV4 reports whether the state file's key check requires MAC4: the
// token expiry and canary fields have been used, and the release before
// them refuses the file until DowngradeV4 is run.
func (s *Store) FormatV4() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.v4 || s.st.hasNewer4()
}

// V4Dropped is what DowngradeV4 removed.
type V4Dropped struct {
	Expiring   []string // tokens that had an expiry: they never expire now
	Renewals   []string // pending renewal requests, dropped
	Unpaired   []string // tokens deleted: renewed, new token never collected
	Rotations  []string // collected renewals: the old token no longer works
	Canaries   []string // secrets no longer canaries
	CanaryHits int      // undismissed canary reads dropped from the Inbox
	RevokeOn   bool     // "revoke a token that reads a canary" was on
}

// DowngradeV4 rewrites the state so the release before token expiry and
// canaries can read it: those fields are removed and the key check goes
// back to the one that requires only MAC..MAC3. A token whose renewal was
// approved but not collected is deleted, since nobody holds a token that
// works for it (the agent must pair again); one that was collected keeps
// its new token. It reports what was dropped; on a file without the
// fields it does nothing.
func (s *Store) DowngradeV4() (V4Dropped, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var d V4Dropped
	if !s.v4 && !s.st.hasNewer4() {
		return d, false, nil
	}
	snap := s.st.clone()
	names := make([]string, 0, len(s.st.Tokens))
	for name := range s.st.Tokens {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		t := s.st.Tokens[name]
		if t.Rotation != nil && t.Rotation.Collected == nil {
			delete(s.st.Tokens, name)
			s.forgetToken(name)
			d.Unpaired = append(d.Unpaired, name)
			continue
		}
		if t.Rotation != nil {
			d.Rotations = append(d.Rotations, name)
		}
		if t.ExpiresAt != nil {
			d.Expiring = append(d.Expiring, name)
		}
		if t.Renewal != nil {
			d.Renewals = append(d.Renewals, name)
		}
		t.ExpiresAt, t.Lifetime, t.Renewal, t.Rotation = nil, 0, nil, nil
	}
	keys := make([]string, 0, len(s.st.Secrets))
	for k := range s.st.Secrets {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		if sec := s.st.Secrets[k]; sec.Canary {
			sec.Canary = false
			d.Canaries = append(d.Canaries, k)
		}
	}
	c := s.st.canary()
	d.CanaryHits, d.RevokeOn = len(c.Hits), c.RevokeOnRead
	s.st.Canary = nil
	oldCheck, oldV4 := s.st.KeyCheck, s.v4
	s.st.KeyCheck = s.seal([]byte(keyCheckMAC), "keycheck")
	s.v4 = false
	if err := s.commit(snap); err != nil {
		s.st.KeyCheck, s.v4 = oldCheck, oldV4
		return V4Dropped{}, false, err
	}
	return d, true, nil
}

// SetClock replaces the store's clock, for tests that need tokens to
// expire.
func (s *Store) SetClock(now func() time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.now = now
}
