// Package store holds keydrop's state: secrets, agent tokens and the admin
// login. Everything lives in one JSON file. Secret values (and the TOTP seed)
// are encrypted individually with AES-256-GCM under the master key, which is
// never written to the data directory.
package store

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"
)

var (
	ErrNotFound    = errors.New("not found")
	ErrExists      = errors.New("already exists")
	ErrNoValue     = errors.New("secret has no value yet")
	ErrNoPrevious  = errors.New("no previous value to roll back to")
	ErrSource      = errors.New("token not allowed from this address")
	ErrBadSource   = errors.New("allowed sources must be IP addresses or CIDR ranges, like 10.0.0.5 or 10.0.0.0/24")
	ErrNotVariable = errors.New("not a variable")
	ErrBadName     = errors.New("namespace and token names must match [a-z0-9][a-z0-9._-]{0,63}")
	ErrBadSecret   = errors.New("secret names are env-var style: capital letters, digits and '_', not starting with a digit (CLOUDFLARE_API_TOKEN)")
	// ErrRequestedByOther: another token already has a pending request for
	// this name, and only it (or the admin) may change the request.
	ErrRequestedByOther = errors.New("already requested by another agent")
	// ErrIntegrity: the state file was changed by something without the
	// master key.
	// ErrNeedsUpgrade: the state file is in the format of a release before
	// the integrity check, which the server doesn't upgrade on its own.
	ErrNeedsUpgrade = errors.New("keydrop.json is in the format of an older release, without the integrity check, and keydrop no longer upgrades it on start. " +
		"Stop keydrop, back up the data directory, and run `keydrop upgrade-data` once with the same data directory and master key " +
		"(see Upgrading and rolling back in the README), then start it again")
	ErrIntegrity = errors.New("keydrop.json failed its integrity check (HMAC): it was changed outside keydrop, or by something without the master key; refusing to start. Restore it from a backup")
)

const (
	stateFile = "keydrop.json"
	// keyCheck is sealed into the state so a wrong master key is caught at
	// start. keyCheckV1 is the pre-MAC format; keyCheckMAC says the state
	// file carries an HMAC and must have a valid one. A v1 key check can't
	// be made without the master key, but one can be copied from an old
	// backup, so Open refuses v1 outright instead of trusting (and
	// upgrading) whatever file carries it; only `keydrop upgrade-data`,
	// run by the operator, upgrades one.
	keyCheckV1  = "keydrop-key-check"
	keyCheckMAC = "keydrop-key-check:v2"
	// TokenPrefix makes leaked tokens easy to recognise and grep for.
	TokenPrefix = "kd_"
)

var (
	nameRE   = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,63}$`)
	secretRE = regexp.MustCompile(`^[A-Z_][A-Z0-9_]{0,63}$`)
)

// ValidName reports whether s is usable as a namespace or token name.
func ValidName(s string) bool { return nameRE.MatchString(s) }

// ValidSecretName reports whether s is usable as a secret name. Secret names
// are env-var style so "keydrop run -e NAME" can inject a secret under its
// own name with nothing to translate.
func ValidSecretName(s string) bool { return secretRE.MatchString(s) }

// Secret is one stored secret or variable. Value and Previous are
// ciphertext. A variable is a non-secret setting (a URL, a username): agents
// may print it, it isn't masked, and reading it isn't recorded. Secrets and
// variables share one set of names, so -e NAME is never ambiguous.
type Secret struct {
	Namespace   string     `json:"namespace"`
	Name        string     `json:"name"`
	Variable    bool       `json:"variable,omitempty"`
	Description string     `json:"description,omitempty"`
	Usage       string     `json:"usage,omitempty"`
	Expires     *time.Time `json:"expires,omitempty"`
	Value       []byte     `json:"value,omitempty"`
	Previous    []byte     `json:"previous,omitempty"`
	// PreviousVariable is Previous's own kind. Kind belongs to each value,
	// so rolling back after a kind change can't turn an old secret value
	// into a variable that's listed, unmasked and read without a log.
	PreviousVariable bool   `json:"previous_variable,omitempty"`
	Pending          bool   `json:"pending,omitempty"` // requested by an agent, waiting for a value
	RequestedBy      string `json:"requested_by,omitempty"`
	New              bool   `json:"new,omitempty"` // value changed and no agent has acknowledged it yet
	// AckedBy names the tokens that acknowledged the current value. Each
	// token's inbox is its own, so one agent's ack doesn't hide a change
	// from another. Cleared when the value changes.
	AckedBy    []string   `json:"acked_by,omitempty"`
	CreatedAt  time.Time  `json:"created_at"`
	UpdatedAt  time.Time  `json:"updated_at"`
	LastReadAt *time.Time `json:"last_read_at,omitempty"`
	LastReadBy string     `json:"last_read_by,omitempty"`
	// Ext holds everything added after the first integrity-checked format
	// (status, flags, notes, proposals). It's nil when there's nothing, so
	// such a secret is stored exactly as before (see legacyView).
	Ext *SecretExt `json:"ext,omitempty"`
}

// Ref is the "namespace/name" form used everywhere outside the store.
func (s Secret) Ref() string { return s.Namespace + "/" + s.Name }

// HasValue reports whether a value has been set.
func (s Secret) HasValue() bool { return len(s.Value) > 0 }

// NewFor reports whether the current value is new to the token named tok:
// changed since it last acknowledged it. Before any agent acknowledges a
// change it's new to all of them; after that, only to those that haven't.
func (s Secret) NewFor(tok string) bool {
	if !s.HasValue() {
		return false
	}
	return s.New || (len(s.AckedBy) > 0 && !slices.Contains(s.AckedBy, tok))
}

// Kind is "variable" or "secret", for display.
func (s Secret) Kind() string {
	if s.Variable {
		return "variable"
	}
	return "secret"
}

// Meta is the human-written description of a secret, and its kind.
type Meta struct {
	Description string
	Usage       string
	Expires     *time.Time
	Variable    bool
}

// Token is an agent's credential. Only the SHA-256 of the token is stored;
// tokens are 256-bit random, so a slow hash adds nothing.
type Token struct {
	Name       string   `json:"name"`
	Hash       string   `json:"hash"`
	Namespaces []string `json:"namespaces"`
	Write      bool     `json:"write,omitempty"` // may create and replace secrets in its namespaces
	// Sources are the CIDR ranges the token may be used from. Empty means
	// any address. A leaked token is then useless from another machine.
	Sources      []string   `json:"sources,omitempty"`
	CreatedAt    time.Time  `json:"created_at"`
	LastUsedAt   *time.Time `json:"last_used_at,omitempty"`
	LastUsedFrom string     `json:"last_used_from,omitempty"`
	// CollectBy is set on a token made by pairing until the agent collects
	// it. Stored, so a token nobody collected is still revoked after a
	// restart.
	CollectBy *time.Time `json:"collect_by,omitempty"`
	// Add is the middle permission: create new keys, and replace the value
	// only of keys this token created. Write wins if both are set. An
	// older release ignores the field, so to it an add token is read-only.
	Add bool `json:"add,omitempty"`
	// Label is the optional agent label a request carried (Claude, Codex
	// sharing one token). Never stored; it only goes into the audit log.
	Label string `json:"-"`
}

// AllowsFrom reports whether the token may be used from address ip.
func (t *Token) AllowsFrom(ip string) bool {
	if len(t.Sources) == 0 {
		return true
	}
	a, err := netip.ParseAddr(ip)
	if err != nil {
		return false
	}
	a = a.Unmap().WithZone("")
	for _, src := range t.Sources {
		if p, err := netip.ParsePrefix(src); err == nil && p.Contains(a) {
			return true
		}
	}
	return false
}

// ParseSources reads a comma- or space-separated list of addresses and CIDR
// ranges into canonical prefixes (a bare address becomes /32 or /128).
func ParseSources(list string) ([]string, error) {
	var out []string
	for _, f := range strings.FieldsFunc(list, func(c rune) bool { return c == ',' || c == ' ' || c == '\n' || c == '\r' || c == '\t' }) {
		var p netip.Prefix
		if a, err := netip.ParseAddr(f); err == nil {
			a = a.Unmap()
			if a.Zone() != "" {
				return nil, ErrBadSource
			}
			p = netip.PrefixFrom(a, a.BitLen())
		} else if p, err = netip.ParsePrefix(f); err != nil {
			return nil, ErrBadSource
		}
		if p.Addr().Is4In6() {
			// Incoming addresses are compared unmapped, so a mapped range
			// would never match: store it as the IPv4 range it means.
			if p.Bits() < 96 {
				return nil, ErrBadSource
			}
			p = netip.PrefixFrom(p.Addr().Unmap(), p.Bits()-96)
		}
		if p.Addr().Zone() != "" {
			return nil, ErrBadSource
		}
		p = p.Masked()
		if !slices.Contains(out, p.String()) {
			out = append(out, p.String())
		}
	}
	return out, nil
}

// Allows reports whether the token is granted namespace ns.
func (t *Token) Allows(ns string) bool {
	for _, n := range t.Namespaces {
		if n == ns {
			return true
		}
	}
	return false
}

type admin struct {
	PasswordHash string `json:"password_hash,omitempty"`
	TOTPSecret   []byte `json:"totp_secret,omitempty"` // encrypted
	TOTPLastStep int64  `json:"totp_last_step,omitempty"`
}

type state struct {
	Version  int                `json:"version"`
	KeyCheck []byte             `json:"key_check"`
	Admin    admin              `json:"admin"`
	Secrets  map[string]*Secret `json:"secrets"`
	Tokens   map[string]*Token  `json:"tokens"`
	// History is the change log agents read with `keydrop history`,
	// oldest first, capped at maxHistory.
	History []Event `json:"history,omitempty"`
	// MAC is HMAC-SHA256 over the rest of the state, with a key derived
	// from the master key, so the file can't be edited (a token hash
	// added, the admin password replaced) without it. It covers the
	// legacy view (the state without the newer fields), which is exactly
	// what an older release reads and checks, so it can still start on
	// this file.
	MAC []byte `json:"mac,omitempty"`
	// MAC2 covers the whole state, newer fields included. It's required
	// whenever any newer field is set, so they can't be edited either;
	// stripping all of them and MAC2 together gives the file an older
	// release would have written (see the design doc).
	MAC2 []byte `json:"mac2,omitempty"`
}

// legacyView is the state as a release from before the newer fields sees
// it: they're all dropped. Marshalled, it's byte-for-byte what that
// release marshals, so both compute the same MAC.
func (st *state) legacyView() state {
	c := *st
	c.MAC, c.MAC2, c.History = nil, nil, nil
	c.Secrets = make(map[string]*Secret, len(st.Secrets))
	for k, v := range st.Secrets {
		cp := *v
		cp.Ext = nil
		c.Secrets[k] = &cp
	}
	c.Tokens = make(map[string]*Token, len(st.Tokens))
	for k, v := range st.Tokens {
		cp := *v
		cp.Add = false
		c.Tokens[k] = &cp
	}
	return c
}

// hasNewer reports whether any field outside the legacy view is set.
func (st *state) hasNewer() bool {
	if len(st.History) > 0 {
		return true
	}
	for _, v := range st.Secrets {
		if v.Ext != nil {
			return true
		}
	}
	for _, v := range st.Tokens {
		if v.Add {
			return true
		}
	}
	return false
}

// clone copies the state deeply enough to undo any mutation: the maps and
// the structs they point to. Slices and pointers inside them are only ever
// replaced, never written through, so sharing them is safe.
func (st *state) clone() state {
	c := *st
	c.Secrets = make(map[string]*Secret, len(st.Secrets))
	for k, v := range st.Secrets {
		cp := *v
		c.Secrets[k] = &cp
	}
	c.Tokens = make(map[string]*Token, len(st.Tokens))
	for k, v := range st.Tokens {
		cp := *v
		c.Tokens[k] = &cp
	}
	return c
}

// Store is safe for concurrent use. Every mutation is written to disk before
// the method returns.
type Store struct {
	mu     sync.Mutex
	path   string
	aead   cipher.AEAD
	master []byte
	st     state
	now    func() time.Time
	macKey []byte
	// mac2Key keys MAC2, independent of macKey.
	mac2Key []byte
	// legacy: the state file is in the format before the integrity check
	// (only ever loaded by OpenExisting).
	legacy bool
}

// ParseKey accepts a 32-byte master key as base64 (standard or URL) or hex.
func ParseKey(s string) ([]byte, error) {
	s = strings.TrimSpace(s)
	for _, dec := range []func(string) ([]byte, error){
		base64.StdEncoding.DecodeString,
		base64.RawStdEncoding.DecodeString,
		base64.URLEncoding.DecodeString,
		base64.RawURLEncoding.DecodeString,
		hex.DecodeString,
	} {
		if b, err := dec(s); err == nil && len(b) == 32 {
			return b, nil
		}
	}
	return nil, errors.New("master key must be 32 bytes, base64 or hex encoded (generate one with `keydrop genkey`)")
}

// GenerateKey returns a new random master key, base64 encoded.
func GenerateKey() string {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return base64.StdEncoding.EncodeToString(b)
}

// Open loads the state file in dir, or creates a new one if there is none.
// A state file in the format before the integrity check is refused with
// ErrNeedsUpgrade: the server never upgrades one on its own, because the
// old format has nothing to check, so anyone who can write the file could
// put an edited one there to be vouched for.
func Open(dir string, key []byte) (*Store, error) {
	s, err := newStore(dir, key)
	if err != nil {
		return nil, err
	}
	data, err := os.ReadFile(s.path)
	switch {
	case errors.Is(err, os.ErrNotExist):
		s.st = state{Version: 1, Secrets: map[string]*Secret{}, Tokens: map[string]*Token{}}
		s.st.KeyCheck = s.seal([]byte(keyCheckMAC), "keycheck")
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return nil, err
		}
		if err := s.save(); err != nil {
			return nil, err
		}
		return s, nil
	case err != nil:
		return nil, err
	}
	if err := s.load(data); err != nil {
		return nil, err
	}
	if s.legacy {
		return nil, ErrNeedsUpgrade
	}
	return s, nil
}

// OpenExisting loads the state file in dir for the data commands
// (upgrade-data, downgrade-data, rotate-tls), and changes nothing. Unlike
// Open it accepts the format before the integrity check (Legacy reports
// it), and it never creates a state file: a missing one is an error, since
// it usually means the wrong directory.
func OpenExisting(dir string, key []byte) (*Store, error) {
	s, err := newStore(dir, key)
	if err != nil {
		return nil, err
	}
	data, err := os.ReadFile(s.path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("there's no %s in %s: check KEYDROP_DATA_DIR and the volume mount", stateFile, dir)
	} else if err != nil {
		return nil, err
	}
	if err := s.load(data); err != nil {
		return nil, err
	}
	return s, nil
}

func newStore(dir string, key []byte) (*Store, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	s := &Store{path: filepath.Join(dir, stateFile), aead: aead, master: slices.Clone(key), now: time.Now}
	s.macKey = s.DeriveKey("state mac")
	s.mac2Key = s.DeriveKey("state mac v2")
	return s, nil
}

// load parses a state file, checks the master key, and checks the HMAC if
// the sealed key check says one is required.
func (s *Store) load(data []byte) error {
	if err := json.Unmarshal(data, &s.st); err != nil {
		return fmt.Errorf("reading %s: %w", s.path, err)
	}
	pt, err := s.open(s.st.KeyCheck, "keycheck")
	if err != nil || (string(pt) != keyCheckV1 && string(pt) != keyCheckMAC) {
		return errors.New("master key does not match this data directory")
	}
	s.legacy = string(pt) == keyCheckV1
	if !s.legacy {
		if !hmac.Equal(s.st.MAC, s.mac()) {
			return ErrIntegrity
		}
		// Newer fields are only trusted under MAC2. Without it the file
		// must have none: what an older release writes.
		if (s.st.hasNewer() || s.st.MAC2 != nil) && !hmac.Equal(s.st.MAC2, s.mac2()) {
			return ErrIntegrity
		}
	}
	if s.st.Secrets == nil {
		s.st.Secrets = map[string]*Secret{}
	}
	if s.st.Tokens == nil {
		s.st.Tokens = map[string]*Token{}
	}
	return nil
}

// Legacy reports whether the state file is in the format before the
// integrity check (written by an older release, or by Downgrade).
func (s *Store) Legacy() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.legacy
}

// Upgrade adds the integrity check to a state file in the older format: an
// HMAC, and a sealed key check that says one is required from now on. It
// vouches for the file exactly as it is, so it's an explicit operator step
// (`keydrop upgrade-data`), never automatic. It reports whether anything
// changed; on a file that already has the check it does nothing.
func (s *Store) Upgrade() (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.legacy {
		return false, nil
	}
	snap := s.st.clone()
	s.st.KeyCheck = s.seal([]byte(keyCheckMAC), "keycheck")
	if err := s.commit(snap); err != nil {
		return false, fmt.Errorf("adding an integrity check to %s: %w", s.path, err)
	}
	s.legacy = false
	return true, nil
}

// mac is the HMAC of the legacy view of the state (see legacyView).
func (s *Store) mac() []byte {
	c := s.st.legacyView()
	return macOf(s.macKey, &c)
}

// mac2 is the HMAC of the whole state with both MAC fields empty.
func (s *Store) mac2() []byte {
	c := s.st
	c.MAC, c.MAC2 = nil, nil
	return macOf(s.mac2Key, &c)
}

func macOf(key []byte, st *state) []byte {
	data, err := json.Marshal(st)
	if err != nil {
		panic(err) // the state is always marshalable
	}
	m := hmac.New(sha256.New, key)
	m.Write(data)
	return m.Sum(nil)
}

// Downgrade rewrites the state so the release before the integrity check
// can read it again: the key check goes back to the old format. The MAC
// stays in the file (the old release ignores it) but means nothing any
// more: this release refuses the file until `keydrop upgrade-data` is run
// again. It reports whether anything changed.
func (s *Store) Downgrade() (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.legacy {
		return false, nil
	}
	snap := s.st.clone()
	s.st.KeyCheck = s.seal([]byte(keyCheckV1), "keycheck")
	if err := s.commit(snap); err != nil {
		return false, err
	}
	s.legacy = true
	return true, nil
}

// SealBlob encrypts a file-sized blob kept outside the state (the TLS
// key), bound to name so it can't be swapped with another.
func (s *Store) SealBlob(name string, pt []byte) []byte { return s.seal(pt, "blob:"+name) }

// OpenBlob decrypts what SealBlob sealed under the same name.
func (s *Store) OpenBlob(name string, ct []byte) ([]byte, error) { return s.open(ct, "blob:"+name) }

// DeriveKey returns a 32-byte key for purpose, derived from the master key
// with HKDF. Each purpose gets an independent key, none of them the
// encryption key itself.
func (s *Store) DeriveKey(purpose string) []byte {
	k, err := hkdf.Key(sha256.New, s.master, nil, "keydrop "+purpose, 32)
	if err != nil {
		panic(err) // only for impossible lengths
	}
	return k
}

// seal encrypts with the AAD bound to where the ciphertext lives, so a value
// copied onto another secret's record fails to decrypt.
func (s *Store) seal(pt []byte, aad string) []byte {
	nonce := make([]byte, s.aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		panic(err)
	}
	return s.aead.Seal(nonce, nonce, pt, []byte(aad))
}

func (s *Store) open(ct []byte, aad string) ([]byte, error) {
	n := s.aead.NonceSize()
	if len(ct) < n {
		return nil, errors.New("ciphertext too short")
	}
	return s.aead.Open(nil, ct[:n], ct[n:], []byte(aad))
}

// commit saves, or puts the state back to snap if the save fails, so memory
// never shows a change that a restart would undo. Call with s.mu held.
func (s *Store) commit(snap state) error {
	if err := s.save(); err != nil {
		s.st = snap
		return err
	}
	return nil
}

func (s *Store) save() error {
	s.st.MAC, s.st.MAC2 = s.mac(), nil
	if s.st.hasNewer() {
		s.st.MAC2 = s.mac2()
	}
	data, err := json.MarshalIndent(&s.st, "", "  ")
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(s.path), ".keydrop-*.tmp")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmp.Name(), s.path); err != nil {
		return err
	}
	if d, err := os.Open(filepath.Dir(s.path)); err == nil {
		d.Sync()
		d.Close()
	}
	return nil
}

func key(ns, name string) string { return ns + "/" + name }

func copySecret(sec *Secret) Secret {
	c := *sec
	c.Value, c.Previous = nil, nil // ciphertext never leaves the store
	if len(sec.Value) > 0 {
		c.Value = []byte{1} // keeps HasValue() meaningful on copies
	}
	if len(sec.Previous) > 0 {
		c.Previous = []byte{1}
	}
	c.AckedBy = slices.Clone(sec.AckedBy)
	if sec.Ext != nil {
		e := sec.Ext.clone()
		c.Ext = &e
	}
	return c
}

// ---- admin ----

// AdminConfigured reports whether an admin password is set. The
// authenticator (TOTP) is optional.
func (s *Store) AdminConfigured() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.st.Admin.PasswordHash != ""
}

// SetAdmin replaces the admin password hash and TOTP seed. A nil seed means
// password-only login.
func (s *Store) SetAdmin(passwordHash string, totpSecret []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	snap := s.st.clone()
	s.st.Admin = admin{PasswordHash: passwordHash, TOTPSecret: s.sealTOTP(totpSecret)}
	return s.commit(snap)
}

// SetPassword replaces the admin password hash, leaving the authenticator
// as it is.
func (s *Store) SetPassword(passwordHash string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	snap := s.st.clone()
	if s.st.Admin.PasswordHash == "" {
		return ErrNotFound
	}
	s.st.Admin.PasswordHash = passwordHash
	return s.commit(snap)
}

// SetTOTP turns the authenticator on with a new seed, or off with nil. The
// last used step is kept, so old codes stay unusable.
func (s *Store) SetTOTP(seed []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	snap := s.st.clone()
	if s.st.Admin.PasswordHash == "" {
		return ErrNotFound
	}
	s.st.Admin.TOTPSecret = s.sealTOTP(seed)
	return s.commit(snap)
}

func (s *Store) sealTOTP(seed []byte) []byte {
	if len(seed) == 0 {
		return nil
	}
	return s.seal(seed, "totp")
}

// TOTPEnabled reports whether login needs an authenticator code.
func (s *Store) TOTPEnabled() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.st.Admin.TOTPSecret) > 0
}

// Admin returns the password hash, the decrypted TOTP seed (nil when the
// authenticator is off) and the last TOTP step accepted (for replay
// protection).
func (s *Store) Admin() (string, []byte, int64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.st.Admin.PasswordHash == "" {
		return "", nil, 0, ErrNotFound
	}
	if len(s.st.Admin.TOTPSecret) == 0 {
		return s.st.Admin.PasswordHash, nil, s.st.Admin.TOTPLastStep, nil
	}
	seed, err := s.open(s.st.Admin.TOTPSecret, "totp")
	return s.st.Admin.PasswordHash, seed, s.st.Admin.TOTPLastStep, err
}

// UseTOTPStep records step as used. It fails if step is not newer than the
// last one, so a code can't be replayed.
func (s *Store) UseTOTPStep(step int64) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	snap := s.st.clone()
	if step <= s.st.Admin.TOTPLastStep {
		return errors.New("code already used")
	}
	s.st.Admin.TOTPLastStep = step
	return s.commit(snap)
}

// ---- secrets ----

// ListSecrets returns metadata copies (no values) sorted by ref, filtered by
// keep if it's non-nil.
func (s *Store) ListSecrets(keep func(*Secret) bool) []Secret {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := []Secret{}
	for _, sec := range s.st.Secrets {
		if keep == nil || keep(sec) {
			out = append(out, copySecret(sec))
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Ref() < out[j].Ref() })
	return out
}

// GetSecret returns a metadata copy.
func (s *Store) GetSecret(ns, name string) (Secret, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	sec, ok := s.st.Secrets[key(ns, name)]
	if !ok {
		return Secret{}, false
	}
	return copySecret(sec), true
}

// PutValue creates or replaces a secret's value. The old value is kept as
// Previous so a bad paste can be rolled back. meta is applied if non-nil.
func (s *Store) PutValue(ns, name string, value []byte, meta *Meta) error {
	_, err := s.putValue(ns, name, value, meta, true, nil)
	return err
}

// CreateValue is PutValue that refuses (ErrExists) to replace a value. The
// check and the write happen under one lock, so two writers can't both
// see "empty" and the second silently replace the first.
func (s *Store) CreateValue(ns, name string, value []byte, meta *Meta) error {
	_, err := s.putValue(ns, name, value, meta, false, nil)
	return err
}

// AgentPut is how an agent stores a value: what it may replace depends on
// its permission, and the text it sends becomes a proposal for the admin
// to approve, not the description itself.
type AgentPut struct {
	Token       Token
	Overwrite   bool
	Variable    bool
	Description *string // nil: leave as is
	Usage       *string
	Expires     **time.Time // nil: leave as is
}

// PutResult says what an agent's put replaced.
type PutResult struct {
	Existed     bool // there was a value before
	WasVariable bool // ...and it was a variable
}

// AgentPut stores a value for an agent token. Everything is checked under
// one lock: ErrExists when there's a value and Overwrite isn't set,
// ErrReadOnly for a read-only token, ErrNotOwner when an add token tries to
// replace a value (or fill a request) another token or the admin made.
func (s *Store) AgentPut(ns, name string, value []byte, p AgentPut) (PutResult, error) {
	for _, t := range []*string{p.Description, p.Usage} {
		if t != nil && len(*t) > MaxText {
			return PutResult{}, ErrTooLong
		}
	}
	return s.putValue(ns, name, value, nil, p.Overwrite, &p)
}

func (s *Store) putValue(ns, name string, value []byte, meta *Meta, overwrite bool, ap *AgentPut) (PutResult, error) {
	var res PutResult
	if !ValidName(ns) {
		return res, ErrBadName
	}
	if !ValidSecretName(name) {
		return res, ErrBadSecret
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	snap := s.st.clone()
	now := s.now().UTC()
	sec, ok := s.st.Secrets[key(ns, name)]
	res = PutResult{Existed: ok && len(sec.Value) > 0, WasVariable: ok && sec.Variable}
	if res.Existed && !overwrite {
		return res, ErrExists
	}
	actor := "admin"
	if ap != nil {
		actor = "token:" + ap.Token.Name
		switch ap.Token.Permission() {
		case PermRead:
			return res, ErrReadOnly
		case PermAdd:
			// Only what it made itself: a value it set, or a request it
			// made. Anything else is someone else's to change.
			if ok && (res.Existed && sec.creator() != ap.Token.Name || !res.Existed && sec.RequestedBy != ap.Token.Name) {
				return res, ErrNotOwner
			}
		}
	}
	var prev []byte
	if res.Existed {
		var err error
		if prev, err = s.reseal(sec.Value, ns, name, "value", "previous"); err != nil {
			return res, err
		}
	}
	if !ok {
		sec = &Secret{Namespace: ns, Name: name, CreatedAt: now}
		s.st.Secrets[key(ns, name)] = sec
	}
	if prev != nil {
		sec.Previous, sec.PreviousVariable = prev, sec.Variable
	}
	sec.Value = s.seal(value, aad(ns, name, "value"))
	sec.Pending, sec.New, sec.AckedBy, sec.UpdatedAt = false, true, nil, now
	if meta != nil {
		applyMeta(sec, *meta)
	}
	if ap != nil {
		sec.Variable = ap.Variable // never inherited: see the API's put
		if ap.Expires != nil {
			sec.Expires = *ap.Expires
		}
		e := sec.ext()
		if !res.Existed {
			e.CreatedBy = ap.Token.Name
		}
		if ap.Description != nil || ap.Usage != nil {
			pr := Proposal{Description: sec.Description, Usage: sec.Usage, By: ap.Token.Name, At: now}
			if e.Proposal != nil {
				pr.Description, pr.Usage = e.Proposal.Description, e.Proposal.Usage
			}
			if ap.Description != nil {
				pr.Description = *ap.Description
			}
			if ap.Usage != nil {
				pr.Usage = *ap.Usage
			}
			if pr.Description != sec.Description || pr.Usage != sec.Usage {
				e.Proposal = &pr
			}
		}
		sec.setExt(e)
	}
	action := "created"
	if res.Existed {
		action = "replaced"
	}
	s.record(Event{Namespace: ns, Name: name, Action: action, Actor: actor, Detail: sec.Kind()})
	return res, s.commit(snap)
}

func aad(ns, name, field string) string { return field + ":" + key(ns, name) }

// reseal moves ciphertext between fields (AAD includes the field name). A
// value that won't decrypt is an error, never an empty value, so a
// rollback can't wipe it.
func (s *Store) reseal(ct []byte, ns, name, from, to string) ([]byte, error) {
	pt, err := s.open(ct, aad(ns, name, from))
	if err != nil {
		return nil, fmt.Errorf("decrypting %s %s: %w", from, key(ns, name), err)
	}
	return s.seal(pt, aad(ns, name, to)), nil
}

func applyMeta(sec *Secret, m Meta) {
	sec.Description, sec.Usage, sec.Expires, sec.Variable = m.Description, m.Usage, m.Expires, m.Variable
}

// UpdateMeta changes description, usage and expiry without touching the value.
func (s *Store) UpdateMeta(ns, name string, m Meta) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	snap := s.st.clone()
	sec, ok := s.st.Secrets[key(ns, name)]
	if !ok {
		return ErrNotFound
	}
	applyMeta(sec, m)
	sec.UpdatedAt = s.now().UTC()
	if sec.Ext != nil && sec.Ext.DescriptionBy != "" {
		e := sec.ext()
		e.DescriptionBy = "" // the admin's text now
		sec.setExt(e)
	}
	s.record(Event{Namespace: ns, Name: name, Action: "details changed", Actor: "admin"})
	return s.commit(snap)
}

// Request creates an empty placeholder for the admin to fill in. The
// description and usage the agent sends are a proposal: no other agent
// sees them until the admin approves. The token that made a pending
// request may update it; any other gets ErrRequestedByOther. Requesting
// one that already has a value fails with ErrExists.
func (s *Store) Request(ns, name, description, usage, by string) error {
	if !ValidName(ns) {
		return ErrBadName
	}
	if !ValidSecretName(name) {
		return ErrBadSecret
	}
	if len(description) > MaxText || len(usage) > MaxText {
		return ErrTooLong
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	snap := s.st.clone()
	now := s.now().UTC()
	sec, ok := s.st.Secrets[key(ns, name)]
	if ok && !sec.Pending {
		return ErrExists
	}
	if ok && sec.RequestedBy != by {
		return ErrRequestedByOther
	}
	if !ok {
		sec = &Secret{Namespace: ns, Name: name, CreatedAt: now}
		s.st.Secrets[key(ns, name)] = sec
	}
	sec.Pending, sec.RequestedBy, sec.UpdatedAt = true, by, now
	e := sec.ext()
	e.Proposal = nil
	if description != "" || usage != "" {
		e.Proposal = &Proposal{Description: description, Usage: usage, By: by, At: now}
	}
	sec.setExt(e)
	if !ok {
		s.record(Event{Namespace: ns, Name: name, Action: "requested", Actor: "token:" + by})
	}
	return s.commit(snap)
}

// Delete removes a secret.
func (s *Store) Delete(ns, name string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	snap := s.st.clone()
	if _, ok := s.st.Secrets[key(ns, name)]; !ok {
		return ErrNotFound
	}
	delete(s.st.Secrets, key(ns, name))
	s.record(Event{Namespace: ns, Name: name, Action: "deleted", Actor: "admin"})
	return s.commit(snap)
}

// Rollback swaps the current and previous values.
func (s *Store) Rollback(ns, name string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	snap := s.st.clone()
	sec, ok := s.st.Secrets[key(ns, name)]
	if !ok {
		return ErrNotFound
	}
	if len(sec.Previous) == 0 {
		return ErrNoPrevious
	}
	var cur []byte
	if len(sec.Value) > 0 {
		var err error
		if cur, err = s.reseal(sec.Value, ns, name, "value", "previous"); err != nil {
			return err
		}
	}
	old, err := s.reseal(sec.Previous, ns, name, "previous", "value")
	if err != nil {
		return err
	}
	sec.Value, sec.Previous = old, cur
	sec.Variable, sec.PreviousVariable = sec.PreviousVariable, sec.Variable
	sec.New, sec.AckedBy, sec.UpdatedAt = true, nil, s.now().UTC()
	s.record(Event{Namespace: ns, Name: name, Action: "rolled back", Actor: "admin", Detail: sec.Kind()})
	return s.commit(snap)
}

// Reveal decrypts a value and, for a secret, records who read it. variable
// is the kind read under the same lock as the value, so callers deciding
// whether to audit or mask can't be fooled by a kind change in between.
func (s *Store) Reveal(ns, name, by string) (value []byte, variable bool, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	snap := s.st.clone()
	sec, ok := s.st.Secrets[key(ns, name)]
	if !ok {
		return nil, false, ErrNotFound
	}
	if len(sec.Value) == 0 {
		return nil, sec.Variable, ErrNoValue
	}
	pt, err := s.open(sec.Value, aad(ns, name, "value"))
	if err != nil {
		return nil, false, fmt.Errorf("decrypting %s: %w", key(ns, name), err)
	}
	if sec.Variable {
		return pt, true, nil
	}
	now := s.now().UTC()
	sec.LastReadAt, sec.LastReadBy = &now, by
	return pt, false, s.commit(snap)
}

// VariableValue decrypts a variable's value. It refuses secrets, so code
// listing variables can't return a secret's value by mistake (or by a race
// with a kind change).
func (s *Store) VariableValue(ns, name string) ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	sec, ok := s.st.Secrets[key(ns, name)]
	switch {
	case !ok:
		return nil, ErrNotFound
	case !sec.Variable:
		return nil, ErrNotVariable
	case len(sec.Value) == 0:
		return nil, ErrNoValue
	}
	return s.open(sec.Value, aad(ns, name, "value"))
}

// Ack records that the token named by has dealt with the current value. It
// only changes that token's own inbox (see NewFor), and clears the admin's
// "no agent has picked it up yet" badge.
func (s *Store) Ack(ns, name, by string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	snap := s.st.clone()
	sec, ok := s.st.Secrets[key(ns, name)]
	if !ok {
		return ErrNotFound
	}
	if !slices.Contains(sec.AckedBy, by) {
		sec.AckedBy = append(slices.Clone(sec.AckedBy), by)
	}
	sec.New = false
	return s.commit(snap)
}

// forgetAcks drops a revoked token's acks, and its ownership of the keys
// it created, so a new token given the same name starts with its own inbox
// and can't replace them under add permission. Call with s.mu held.
func (s *Store) forgetAcks(tok string) {
	for _, sec := range s.st.Secrets {
		if i := slices.Index(sec.AckedBy, tok); i >= 0 {
			sec.AckedBy = slices.Delete(slices.Clone(sec.AckedBy), i, i+1)
		}
		if sec.Ext != nil && sec.Ext.CreatedBy == tok {
			e := sec.ext()
			e.CreatedBy = ""
			sec.setExt(e)
		}
	}
}

// Namespaces lists every namespace used by a secret or granted to a token.
func (s *Store) Namespaces() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	seen := map[string]bool{}
	for _, sec := range s.st.Secrets {
		seen[sec.Namespace] = true
	}
	for _, t := range s.st.Tokens {
		for _, n := range t.Namespaces {
			seen[n] = true
		}
	}
	out := make([]string, 0, len(seen))
	for n := range seen {
		out = append(out, n)
	}
	sort.Strings(out)
	return out
}

// ---- tokens ----

func hashToken(tok string) string {
	h := sha256.Sum256([]byte(tok))
	return hex.EncodeToString(h[:])
}

// CreateToken makes a new agent token and returns its plaintext. The
// plaintext is not stored and can't be shown again.
// sources limits where it can be used from (see ParseSources); nil is
// anywhere.
func (s *Store) CreateToken(name string, namespaces []string, perm Permission, sources []string) (string, error) {
	return s.createToken(name, namespaces, perm, sources, nil)
}

// CreatePairedToken is CreateToken for pairing: unless Collected is called
// with the token by collectBy, RevokeUncollected deletes it.
func (s *Store) CreatePairedToken(name string, namespaces []string, perm Permission, sources []string, collectBy time.Time) (string, error) {
	return s.createToken(name, namespaces, perm, sources, &collectBy)
}

// CheckToken validates a token's settings without creating it, so a caller
// can check before revoking the token it replaces.
func CheckToken(name string, namespaces []string, sources []string) error {
	if !ValidName(name) || len(namespaces) == 0 {
		return ErrBadName
	}
	for _, src := range sources {
		if _, err := netip.ParsePrefix(src); err != nil {
			return ErrBadSource
		}
	}
	for _, n := range namespaces {
		if !ValidName(n) {
			return ErrBadName
		}
	}
	return nil
}

func (s *Store) createToken(name string, namespaces []string, perm Permission, sources []string, collectBy *time.Time) (string, error) {
	if err := CheckToken(name, namespaces, sources); err != nil {
		return "", err
	}
	if !perm.Valid() {
		return "", ErrBadPermission
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	snap := s.st.clone()
	if _, ok := s.st.Tokens[name]; ok {
		return "", ErrExists
	}
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	plain := TokenPrefix + base64.RawURLEncoding.EncodeToString(b)
	s.st.Tokens[name] = &Token{
		Name: name, Hash: hashToken(plain), Namespaces: namespaces,
		Write: perm == PermWrite, Add: perm == PermAdd, Sources: sources, CreatedAt: s.now().UTC(), CollectBy: collectBy,
	}
	return plain, s.commit(snap)
}

// Collected marks a paired token as handed over. It matches on the token
// itself, not the name, so a token that was since revoked or replaced
// returns ErrNotFound and the newer token of that name is untouched.
func (s *Store) Collected(plain string) error {
	h := hashToken(plain)
	s.mu.Lock()
	defer s.mu.Unlock()
	snap := s.st.clone()
	for _, t := range s.st.Tokens {
		if t.Hash == h {
			t.CollectBy = nil
			return s.commit(snap)
		}
	}
	return ErrNotFound
}

// RevokeUncollected deletes paired tokens whose collection deadline has
// passed by now and returns their names.
func (s *Store) RevokeUncollected(now time.Time) []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	snap := s.st.clone()
	var gone []string
	for name, t := range s.st.Tokens {
		if t.CollectBy != nil && now.After(*t.CollectBy) {
			delete(s.st.Tokens, name)
			gone = append(gone, name)
		}
	}
	if len(gone) > 0 {
		sort.Strings(gone)
		for _, name := range gone {
			s.forgetAcks(name)
		}
		if err := s.commit(snap); err != nil {
			return nil
		}
	}
	return gone
}

// RevokeToken deletes a token.
func (s *Store) RevokeToken(name string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	snap := s.st.clone()
	if _, ok := s.st.Tokens[name]; !ok {
		return ErrNotFound
	}
	delete(s.st.Tokens, name)
	s.forgetAcks(name)
	return s.commit(snap)
}

// LookupToken finds the token matching plain, checks it may be used from
// ip, and records its use. Use from a disallowed address returns the token
// (so it can be named in the log) with ErrSource, and isn't recorded as
// use. Last-used is persisted at most once a minute, to avoid a disk write
// per request.
func (s *Store) LookupToken(plain, ip string) (Token, error) {
	if !strings.HasPrefix(plain, TokenPrefix) {
		return Token{}, ErrNotFound
	}
	h := hashToken(plain)
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, t := range s.st.Tokens {
		if t.Hash == h {
			if !t.AllowsFrom(ip) {
				return *t, ErrSource
			}
			now := s.now().UTC()
			t.LastUsedFrom = ip
			if t.LastUsedAt == nil || now.Sub(*t.LastUsedAt) > time.Minute {
				t.LastUsedAt = &now
				_ = s.save()
			}
			return *t, nil
		}
	}
	return Token{}, ErrNotFound
}

// SetTokenSources replaces where a token may be used from (nil: anywhere).
func (s *Store) SetTokenSources(name string, sources []string) error {
	for _, src := range sources {
		if _, err := netip.ParsePrefix(src); err != nil {
			return ErrBadSource
		}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	snap := s.st.clone()
	t, ok := s.st.Tokens[name]
	if !ok {
		return ErrNotFound
	}
	t.Sources = sources
	return s.commit(snap)
}

// ListTokens returns all tokens sorted by name.
func (s *Store) ListTokens() []Token {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]Token, 0, len(s.st.Tokens))
	for _, t := range s.st.Tokens {
		out = append(out, *t)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}
