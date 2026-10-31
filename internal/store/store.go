// Package store holds keydrop's state: secrets, agent tokens and the admin
// login. Everything lives in one JSON file. Secret values (and the TOTP seed)
// are encrypted individually with AES-256-GCM under the master key, which is
// never written to the data directory.
package store

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"
)

var (
	ErrNotFound   = errors.New("not found")
	ErrExists     = errors.New("already exists")
	ErrNoValue    = errors.New("secret has no value yet")
	ErrNoPrevious = errors.New("no previous value to roll back to")
	ErrBadName    = errors.New("names must match [a-z0-9][a-z0-9._-]{0,63}")
)

const (
	stateFile = "keydrop.json"
	keyCheck  = "keydrop-key-check"
	// TokenPrefix makes leaked tokens easy to recognise and grep for.
	TokenPrefix = "kd_"
)

var nameRE = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,63}$`)

// ValidName reports whether s is usable as a namespace, secret or token name.
func ValidName(s string) bool { return nameRE.MatchString(s) }

// Secret is one stored secret. Value and Previous are ciphertext.
type Secret struct {
	Namespace   string     `json:"namespace"`
	Name        string     `json:"name"`
	Description string     `json:"description,omitempty"`
	Usage       string     `json:"usage,omitempty"`
	Expires     *time.Time `json:"expires,omitempty"`
	Value       []byte     `json:"value,omitempty"`
	Previous    []byte     `json:"previous,omitempty"`
	Pending     bool       `json:"pending,omitempty"` // requested by an agent, waiting for a value
	RequestedBy string     `json:"requested_by,omitempty"`
	New         bool       `json:"new,omitempty"` // value changed and no agent has acknowledged it yet
	CreatedAt   time.Time  `json:"created_at"`
	UpdatedAt   time.Time  `json:"updated_at"`
	LastReadAt  *time.Time `json:"last_read_at,omitempty"`
	LastReadBy  string     `json:"last_read_by,omitempty"`
}

// Ref is the "namespace/name" form used everywhere outside the store.
func (s Secret) Ref() string { return s.Namespace + "/" + s.Name }

// HasValue reports whether a value has been set.
func (s Secret) HasValue() bool { return len(s.Value) > 0 }

// Meta is the human-written description of a secret.
type Meta struct {
	Description string
	Usage       string
	Expires     *time.Time
}

// Token is an agent's credential. Only the SHA-256 of the token is stored;
// tokens are 256-bit random, so a slow hash adds nothing.
type Token struct {
	Name       string     `json:"name"`
	Hash       string     `json:"hash"`
	Namespaces []string   `json:"namespaces"`
	Write      bool       `json:"write,omitempty"` // may create and replace secrets in its namespaces
	CreatedAt  time.Time  `json:"created_at"`
	LastUsedAt *time.Time `json:"last_used_at,omitempty"`
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
}

// Store is safe for concurrent use. Every mutation is written to disk before
// the method returns.
type Store struct {
	mu   sync.Mutex
	path string
	aead cipher.AEAD
	st   state
	now  func() time.Time
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

// Open loads (or creates) the state file in dir.
func Open(dir string, key []byte) (*Store, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	s := &Store{path: filepath.Join(dir, stateFile), aead: aead, now: time.Now}
	data, err := os.ReadFile(s.path)
	switch {
	case errors.Is(err, os.ErrNotExist):
		s.st = state{Version: 1, Secrets: map[string]*Secret{}, Tokens: map[string]*Token{}}
		s.st.KeyCheck = s.seal([]byte(keyCheck), "keycheck")
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
	if err := json.Unmarshal(data, &s.st); err != nil {
		return nil, fmt.Errorf("reading %s: %w", s.path, err)
	}
	if pt, err := s.open(s.st.KeyCheck, "keycheck"); err != nil || string(pt) != keyCheck {
		return nil, errors.New("master key does not match this data directory")
	}
	if s.st.Secrets == nil {
		s.st.Secrets = map[string]*Secret{}
	}
	if s.st.Tokens == nil {
		s.st.Tokens = map[string]*Token{}
	}
	return s, nil
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

func (s *Store) save() error {
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
	return c
}

// ---- admin ----

// AdminConfigured reports whether the admin password and TOTP are set.
func (s *Store) AdminConfigured() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.st.Admin.PasswordHash != "" && len(s.st.Admin.TOTPSecret) > 0
}

// SetAdmin replaces the admin password hash and TOTP seed.
func (s *Store) SetAdmin(passwordHash string, totpSecret []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.st.Admin = admin{PasswordHash: passwordHash, TOTPSecret: s.seal(totpSecret, "totp")}
	return s.save()
}

// Admin returns the password hash, decrypted TOTP seed and the last TOTP
// step accepted (for replay protection).
func (s *Store) Admin() (string, []byte, int64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.st.Admin.PasswordHash == "" {
		return "", nil, 0, ErrNotFound
	}
	seed, err := s.open(s.st.Admin.TOTPSecret, "totp")
	return s.st.Admin.PasswordHash, seed, s.st.Admin.TOTPLastStep, err
}

// UseTOTPStep records step as used. It fails if step is not newer than the
// last one, so a code can't be replayed.
func (s *Store) UseTOTPStep(step int64) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if step <= s.st.Admin.TOTPLastStep {
		return errors.New("code already used")
	}
	s.st.Admin.TOTPLastStep = step
	return s.save()
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
	if !ValidName(ns) || !ValidName(name) {
		return ErrBadName
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now().UTC()
	sec, ok := s.st.Secrets[key(ns, name)]
	if !ok {
		sec = &Secret{Namespace: ns, Name: name, CreatedAt: now}
		s.st.Secrets[key(ns, name)] = sec
	}
	if len(sec.Value) > 0 {
		sec.Previous = s.reseal(sec.Value, ns, name, "value", "previous")
	}
	sec.Value = s.seal(value, aad(ns, name, "value"))
	sec.Pending, sec.New, sec.UpdatedAt = false, true, now
	if meta != nil {
		applyMeta(sec, *meta)
	}
	return s.save()
}

func aad(ns, name, field string) string { return field + ":" + key(ns, name) }

// reseal moves ciphertext between fields (AAD includes the field name).
func (s *Store) reseal(ct []byte, ns, name, from, to string) []byte {
	pt, err := s.open(ct, aad(ns, name, from))
	if err != nil {
		return nil
	}
	return s.seal(pt, aad(ns, name, to))
}

func applyMeta(sec *Secret, m Meta) {
	sec.Description, sec.Usage, sec.Expires = m.Description, m.Usage, m.Expires
}

// UpdateMeta changes description, usage and expiry without touching the value.
func (s *Store) UpdateMeta(ns, name string, m Meta) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	sec, ok := s.st.Secrets[key(ns, name)]
	if !ok {
		return ErrNotFound
	}
	applyMeta(sec, m)
	sec.UpdatedAt = s.now().UTC()
	return s.save()
}

// Request creates an empty placeholder for the admin to fill in. Requesting
// one that's already pending updates its description; requesting one that
// already has a value fails with ErrExists.
func (s *Store) Request(ns, name, description, usage, by string) error {
	if !ValidName(ns) || !ValidName(name) {
		return ErrBadName
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now().UTC()
	sec, ok := s.st.Secrets[key(ns, name)]
	if ok && !sec.Pending {
		return ErrExists
	}
	if !ok {
		sec = &Secret{Namespace: ns, Name: name, CreatedAt: now}
		s.st.Secrets[key(ns, name)] = sec
	}
	sec.Pending, sec.RequestedBy, sec.UpdatedAt = true, by, now
	sec.Description, sec.Usage = description, usage
	return s.save()
}

// Delete removes a secret.
func (s *Store) Delete(ns, name string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.st.Secrets[key(ns, name)]; !ok {
		return ErrNotFound
	}
	delete(s.st.Secrets, key(ns, name))
	return s.save()
}

// Rollback swaps the current and previous values.
func (s *Store) Rollback(ns, name string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	sec, ok := s.st.Secrets[key(ns, name)]
	if !ok {
		return ErrNotFound
	}
	if len(sec.Previous) == 0 {
		return ErrNoPrevious
	}
	cur := s.reseal(sec.Value, ns, name, "value", "previous")
	sec.Value = s.reseal(sec.Previous, ns, name, "previous", "value")
	sec.Previous = cur
	sec.New, sec.UpdatedAt = true, s.now().UTC()
	return s.save()
}

// Reveal decrypts a value and records who read it.
func (s *Store) Reveal(ns, name, by string) ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	sec, ok := s.st.Secrets[key(ns, name)]
	if !ok {
		return nil, ErrNotFound
	}
	if len(sec.Value) == 0 {
		return nil, ErrNoValue
	}
	pt, err := s.open(sec.Value, aad(ns, name, "value"))
	if err != nil {
		return nil, fmt.Errorf("decrypting %s: %w", key(ns, name), err)
	}
	now := s.now().UTC()
	sec.LastReadAt, sec.LastReadBy = &now, by
	return pt, s.save()
}

// Ack clears the "new" flag once an agent has dealt with a secret.
func (s *Store) Ack(ns, name string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	sec, ok := s.st.Secrets[key(ns, name)]
	if !ok {
		return ErrNotFound
	}
	sec.New = false
	return s.save()
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
func (s *Store) CreateToken(name string, namespaces []string, write bool) (string, error) {
	if !ValidName(name) || len(namespaces) == 0 {
		return "", ErrBadName
	}
	for _, n := range namespaces {
		if !ValidName(n) {
			return "", ErrBadName
		}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
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
		Write: write, CreatedAt: s.now().UTC(),
	}
	return plain, s.save()
}

// RevokeToken deletes a token.
func (s *Store) RevokeToken(name string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.st.Tokens[name]; !ok {
		return ErrNotFound
	}
	delete(s.st.Tokens, name)
	return s.save()
}

// LookupToken finds the token matching plain and records its use. Last-used
// time is persisted at most once a minute to avoid a disk write per request.
func (s *Store) LookupToken(plain string) (Token, bool) {
	if !strings.HasPrefix(plain, TokenPrefix) {
		return Token{}, false
	}
	h := hashToken(plain)
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, t := range s.st.Tokens {
		if t.Hash == h {
			now := s.now().UTC()
			if t.LastUsedAt == nil || now.Sub(*t.LastUsedAt) > time.Minute {
				t.LastUsedAt = &now
				_ = s.save()
			}
			return *t, true
		}
	}
	return Token{}, false
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
