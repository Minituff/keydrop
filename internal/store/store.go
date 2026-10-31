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
)

const (
	stateFile = "keydrop.json"
	keyCheck  = "keydrop-key-check"
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
	PreviousVariable bool       `json:"previous_variable,omitempty"`
	Pending          bool       `json:"pending,omitempty"` // requested by an agent, waiting for a value
	RequestedBy      string     `json:"requested_by,omitempty"`
	New              bool       `json:"new,omitempty"` // value changed and no agent has acknowledged it yet
	CreatedAt        time.Time  `json:"created_at"`
	UpdatedAt        time.Time  `json:"updated_at"`
	LastReadAt       *time.Time `json:"last_read_at,omitempty"`
	LastReadBy       string     `json:"last_read_by,omitempty"`
}

// Ref is the "namespace/name" form used everywhere outside the store.
func (s Secret) Ref() string { return s.Namespace + "/" + s.Name }

// HasValue reports whether a value has been set.
func (s Secret) HasValue() bool { return len(s.Value) > 0 }

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
	s.st.Admin = admin{PasswordHash: passwordHash, TOTPSecret: s.sealTOTP(totpSecret)}
	return s.save()
}

// SetPassword replaces the admin password hash, leaving the authenticator
// as it is.
func (s *Store) SetPassword(passwordHash string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.st.Admin.PasswordHash == "" {
		return ErrNotFound
	}
	s.st.Admin.PasswordHash = passwordHash
	return s.save()
}

// SetTOTP turns the authenticator on with a new seed, or off with nil. The
// last used step is kept, so old codes stay unusable.
func (s *Store) SetTOTP(seed []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.st.Admin.PasswordHash == "" {
		return ErrNotFound
	}
	s.st.Admin.TOTPSecret = s.sealTOTP(seed)
	return s.save()
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
	if !ValidName(ns) {
		return ErrBadName
	}
	if !ValidSecretName(name) {
		return ErrBadSecret
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
		sec.PreviousVariable = sec.Variable
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
	sec.Description, sec.Usage, sec.Expires, sec.Variable = m.Description, m.Usage, m.Expires, m.Variable
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
	if !ValidName(ns) {
		return ErrBadName
	}
	if !ValidSecretName(name) {
		return ErrBadSecret
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
	sec.Variable, sec.PreviousVariable = sec.PreviousVariable, sec.Variable
	sec.New, sec.UpdatedAt = true, s.now().UTC()
	return s.save()
}

// Reveal decrypts a value and, for a secret, records who read it. variable
// is the kind read under the same lock as the value, so callers deciding
// whether to audit or mask can't be fooled by a kind change in between.
func (s *Store) Reveal(ns, name, by string) (value []byte, variable bool, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
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
	return pt, false, s.save()
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
// sources limits where it can be used from (see ParseSources); nil is
// anywhere.
func (s *Store) CreateToken(name string, namespaces []string, write bool, sources []string) (string, error) {
	return s.createToken(name, namespaces, write, sources, nil)
}

// CreatePairedToken is CreateToken for pairing: unless Collected is called
// with the token by collectBy, RevokeUncollected deletes it.
func (s *Store) CreatePairedToken(name string, namespaces []string, write bool, sources []string, collectBy time.Time) (string, error) {
	return s.createToken(name, namespaces, write, sources, &collectBy)
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

func (s *Store) createToken(name string, namespaces []string, write bool, sources []string, collectBy *time.Time) (string, error) {
	if err := CheckToken(name, namespaces, sources); err != nil {
		return "", err
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
		Write: write, Sources: sources, CreatedAt: s.now().UTC(), CollectBy: collectBy,
	}
	return plain, s.save()
}

// Collected marks a paired token as handed over. It matches on the token
// itself, not the name, so a token that was since revoked or replaced
// returns ErrNotFound and the newer token of that name is untouched.
func (s *Store) Collected(plain string) error {
	h := hashToken(plain)
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, t := range s.st.Tokens {
		if t.Hash == h {
			t.CollectBy = nil
			return s.save()
		}
	}
	return ErrNotFound
}

// RevokeUncollected deletes paired tokens whose collection deadline has
// passed by now and returns their names.
func (s *Store) RevokeUncollected(now time.Time) []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	var gone []string
	for name, t := range s.st.Tokens {
		if t.CollectBy != nil && now.After(*t.CollectBy) {
			delete(s.st.Tokens, name)
			gone = append(gone, name)
		}
	}
	if len(gone) > 0 {
		sort.Strings(gone)
		_ = s.save()
	}
	return gone
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
	t, ok := s.st.Tokens[name]
	if !ok {
		return ErrNotFound
	}
	t.Sources = sources
	return s.save()
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
