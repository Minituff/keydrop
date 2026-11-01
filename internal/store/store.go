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
	"crypto/subtle"
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
	// keyCheckV4 says MAC4 is required too. The fields under MAC4 (token
	// expiry, rotations, canaries) restrict access, so a file with them
	// deleted must not load as one that never had them: once any is
	// written the key check says so, and only `keydrop downgrade-data`
	// (DowngradeV4) takes it back, dropping them knowingly. The release
	// before MAC4 doesn't know this key check, so it refuses the file
	// until that's run.
	keyCheckV4 = "keydrop-key-check:v4"
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
	// Group and Batch came after Ext, in the release after it: outside
	// both older MACs' views (see v2View), so both older releases still
	// open the file. Group is the slug of an explicit group in the same
	// namespace; empty means none (auto or ungrouped, worked out when
	// shown). Batch links a pending request to the others an agent asked
	// for with it.
	Group string        `json:"group,omitempty"`
	Batch *RequestBatch `json:"batch,omitempty"`
	// Canary marks a secret whose value is a decoy: any agent reading it
	// raises an alert. Admin-only; nothing an agent sees shows it. It
	// came after Group and is outside v3View (see there). Only secrets
	// can be canaries: it's cleared when the entry becomes a variable.
	Canary bool `json:"canary,omitempty"`
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
	// ExpiresAt is when the token stops working; nil is never. It's
	// outside v3View, so the release before it (which ignores it) still
	// opens the file, and on a rollback the token just stops expiring.
	ExpiresAt *time.Time `json:"expires_at,omitempty"`
	// Lifetime is the lifetime in days the token was last given (0: never
	// expires, or made before lifetimes), offered again on renewal.
	Lifetime int `json:"lifetime_days,omitempty"`
	// Renewal is the agent's own pending request to extend the token.
	// Like ExpiresAt and Lifetime it's outside v3View.
	Renewal *RenewalRequest `json:"renewal,omitempty"`
	// Rotation is an approved renewal the agent hasn't collected yet (see
	// RotateToken). Outside v3View too.
	Rotation *Rotation `json:"rotation,omitempty"`
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
	// oldest first, capped per namespace (see trimHistory).
	History []Event `json:"history,omitempty"`
	// Fixups is how many of the load-time fix-ups (see fixup) this file
	// has had. Outside the legacy view, so an older release drops it when
	// it rewrites the file, and the fix-ups run again on what it wrote.
	Fixups int `json:"fixups,omitempty"`
	// MAC is HMAC-SHA256 over the rest of the state, with a key derived
	// from the master key, so the file can't be edited (a token hash
	// added, the admin password replaced) without it. It covers the
	// legacy view (the state without the newer fields), which is exactly
	// what an older release reads and checks, so it can still start on
	// this file.
	MAC []byte `json:"mac,omitempty"`
	// MAC2 covers v2View: the state with the newer fields, but not those
	// after it (groups), which MAC3 covers. It's required whenever any
	// newer field is set, so they can't be edited either;
	// stripping all of them and MAC2 together gives the file an older
	// release would have written (see the design doc).
	MAC2 []byte `json:"mac2,omitempty"`
	// Groups (keyed "namespace/slug") and Settings came in the release
	// after MAC2, and MAC3 covers them; see v2View.
	Groups   map[string]*Group `json:"groups,omitempty"`
	Settings *Settings         `json:"settings,omitempty"`
	MAC3     []byte            `json:"mac3,omitempty"`
	// Canary (the canary settings and unseen reads), each secret's Canary
	// flag and each token's ExpiresAt, Lifetime, Renewal and Rotation came in the release after MAC3, and
	// MAC4 covers them; see v3View.
	Canary *CanaryState `json:"canary,omitempty"`
	MAC4   []byte       `json:"mac4,omitempty"`
	// Alerts (the webhook set in Settings) came in the release after
	// MAC4, and MAC5 covers it; see v4View and alerts.go.
	Alerts *AlertSettings `json:"alerts,omitempty"`
	MAC5   []byte         `json:"mac5,omitempty"`
}

// legacyView is the state as a release from before the newer fields sees
// it: they're all dropped. Marshalled, it's byte-for-byte what that
// release marshals, so both compute the same MAC.
func (st *state) legacyView() state {
	c := st.v2View()
	c.History, c.Fixups = nil, 0
	for _, v := range c.Secrets {
		v.Ext = nil // a copy, made by v2View
	}
	for _, v := range c.Tokens {
		v.Add = false // a copy, made by v3View
	}
	return c
}

// v2View is the state as the release with MAC2 (and without groups) sees
// it: groups, settings, each entry's group and batch, and MAC3 dropped,
// the MACs empty. Marshalled, it's byte-for-byte what that release
// marshals for its MAC2, so it still verifies a file this one wrote.
// Pointers inside (Ext) are shared with st: don't write through them.
func (st *state) v2View() state {
	c := st.v3View()
	c.Groups, c.Settings = nil, nil
	for _, v := range c.Secrets {
		v.Group, v.Batch = "", nil // a copy, made by v3View
	}
	return c
}

// v3View is the state as the release with MAC3 (and without canaries and
// token expiry) sees it: the canary state, each secret's Canary flag,
// each token's ExpiresAt, Lifetime, Renewal and Rotation, and MAC4 dropped, the MACs empty. Marshalled,
// it's byte-for-byte what that release marshals for its MAC3, so it still
// verifies a file this one wrote. The maps are copies; pointers inside
// them are shared with st: don't write through them.
func (st *state) v3View() state {
	c := st.v4View()
	c.MAC4, c.Canary = nil, nil
	c.Secrets = make(map[string]*Secret, len(st.Secrets))
	for k, v := range st.Secrets {
		cp := *v
		cp.Canary = false
		c.Secrets[k] = &cp
	}
	c.Tokens = make(map[string]*Token, len(st.Tokens))
	for k, v := range st.Tokens {
		cp := *v
		cp.ExpiresAt, cp.Lifetime, cp.Renewal, cp.Rotation = nil, 0, nil, nil
		c.Tokens[k] = &cp
	}
	return c
}

// v4View is the state as the release with MAC4 (and without the alert
// webhook in Settings) sees it: the alerts field and MAC5 dropped, the MACs
// empty. Marshalled, it's byte-for-byte what that release marshals for its
// MAC4. A shallow copy: don't write through it.
func (st *state) v4View() state {
	c := *st
	c.MAC, c.MAC2, c.MAC3, c.MAC4, c.MAC5, c.Alerts = nil, nil, nil, nil, nil, nil
	return c
}

// hasNewer4 reports whether any field outside v3View is set.
func (st *state) hasNewer4() bool {
	if st.Canary != nil {
		return true
	}
	for _, v := range st.Secrets {
		if v.Canary {
			return true
		}
	}
	for _, v := range st.Tokens {
		if v.ExpiresAt != nil || v.Lifetime != 0 || v.Renewal != nil || v.Rotation != nil {
			return true
		}
	}
	return false
}

// hasNewer3 reports whether any field outside v2View is set.
func (st *state) hasNewer3() bool {
	if len(st.Groups) > 0 || st.Settings != nil {
		return true
	}
	for _, v := range st.Secrets {
		if v.Group != "" || v.Batch != nil {
			return true
		}
	}
	return false
}

// hasNewer reports whether any field outside the legacy view, and inside
// v2View, is set.
func (st *state) hasNewer() bool {
	if len(st.History) > 0 || st.Fixups > 0 {
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
	if st.Groups != nil {
		c.Groups = make(map[string]*Group, len(st.Groups))
		for k, v := range st.Groups {
			cp := *v
			c.Groups[k] = &cp
		}
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
	// mac2Key keys MAC2, mac3Key MAC3, each independent of the others.
	mac2Key []byte
	mac3Key []byte
	mac4Key []byte
	mac5Key []byte
	// legacy: the state file is in the format before the integrity check
	// (only ever loaded by OpenExisting).
	legacy bool
	// v4: the key check says MAC4 is required (keyCheckV4), whatever the
	// file holds. Set the first time a MAC4 field is written; only
	// DowngradeV4 clears it.
	v4 bool
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
		s.st = state{Version: 1, Secrets: map[string]*Secret{}, Tokens: map[string]*Token{}, Fixups: fixupVersion}
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
	if err := s.fixup(); err != nil {
		return nil, fmt.Errorf("updating %s: %w", s.path, err)
	}
	return s, nil
}

// fixupVersion is the number of fix-ups fixup knows.
const fixupVersion = 1

// fixup corrects data an older release wrote that this one would read
// wrongly. It runs only on a file whose MAC verified, changes only what
// that release could also have written, and records that it ran (Fixups),
// so it never touches what this release wrote since.
//
// 1: the release before proposals wrote an agent's request text straight
// into the description, where it would now read as the admin's. On a
// pending request it becomes the requester's proposal again, waiting for
// the admin; on a filled one it stays, marked as written by the requester.
// (A key a write token created with put --desc then left no trace of who
// wrote its description, so that can't be told apart from the admin's.)
func (s *Store) fixup() error {
	if s.st.Fixups >= fixupVersion {
		return nil
	}
	snap := s.st.clone()
	for _, sec := range s.st.Secrets {
		if sec.RequestedBy == "" || (sec.Description == "" && sec.Usage == "") {
			continue
		}
		e := sec.ext()
		if e.DescriptionBy != "" {
			continue
		}
		if sec.Pending && e.Proposal == nil {
			e.Proposal = &Proposal{Description: sec.Description, Usage: sec.Usage, By: sec.RequestedBy, At: sec.UpdatedAt}
			sec.Description, sec.Usage = "", ""
		} else {
			e.DescriptionBy = sec.RequestedBy
		}
		sec.setExt(e)
	}
	s.st.Fixups = fixupVersion
	return s.commit(snap)
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
	s.mac3Key = s.DeriveKey("state mac v3")
	s.mac4Key = s.DeriveKey("state mac v4")
	s.mac5Key = s.DeriveKey("state mac v5")
	return s, nil
}

// load parses a state file, checks the master key, and checks the HMAC if
// the sealed key check says one is required.
func (s *Store) load(data []byte) error {
	if err := json.Unmarshal(data, &s.st); err != nil {
		return fmt.Errorf("reading %s: %w", s.path, err)
	}
	pt, err := s.open(s.st.KeyCheck, "keycheck")
	if err != nil || (string(pt) != keyCheckV1 && string(pt) != keyCheckMAC && string(pt) != keyCheckV4) {
		return errors.New("master key does not match this data directory")
	}
	s.legacy = string(pt) == keyCheckV1
	s.v4 = string(pt) == keyCheckV4
	if !s.legacy {
		if !hmac.Equal(s.st.MAC, s.mac()) {
			return ErrIntegrity
		}
		// Newer fields are only trusted under MAC2. Without it the file
		// must have none: what an older release writes.
		if (s.st.hasNewer() || s.st.MAC2 != nil) && !hmac.Equal(s.st.MAC2, s.mac2()) {
			return ErrIntegrity
		}
		// The same again for the fields after MAC2, under MAC3.
		if (s.st.hasNewer3() || s.st.MAC3 != nil) && !hmac.Equal(s.st.MAC3, s.mac3()) {
			return ErrIntegrity
		}
		// And for the fields after MAC3, under MAC4.
		if (s.v4 || s.st.hasNewer4() || s.st.MAC4 != nil) && !hmac.Equal(s.st.MAC4, s.mac4()) {
			return ErrIntegrity
		}
		// And for the alert webhook, under MAC5.
		if (s.st.Alerts != nil || s.st.MAC5 != nil) && !hmac.Equal(s.st.MAC5, s.mac5()) {
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

// mac2 is the HMAC of v2View: everything the release with MAC2 knows.
func (s *Store) mac2() []byte {
	c := s.st.v2View()
	return macOf(s.mac2Key, &c)
}

// mac3 is the HMAC of v3View: everything the release with MAC3 knows.
func (s *Store) mac3() []byte {
	c := s.st.v3View()
	return macOf(s.mac3Key, &c)
}

// mac4 is the HMAC of v4View: everything the release with MAC4 knows.
func (s *Store) mac4() []byte {
	c := s.st.v4View()
	return macOf(s.mac4Key, &c)
}

// mac5 is the HMAC of the whole state with the MAC fields empty.
func (s *Store) mac5() []byte {
	c := s.st
	c.MAC, c.MAC2, c.MAC3, c.MAC4, c.MAC5 = nil, nil, nil, nil, nil
	return macOf(s.mac5Key, &c)
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
	if s.v4 {
		return false, errors.New("downgrade the token expiry and canary fields first (DowngradeV4)")
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
	if !s.legacy && !s.v4 && s.st.hasNewer4() {
		// From now on MAC4 is required (see keyCheckV4). s.v4 is set only
		// once that's on disk: a failed save restores the old key check.
		old := s.st.KeyCheck
		s.st.KeyCheck = s.seal([]byte(keyCheckV4), "keycheck")
		if err := s.write(true); err != nil {
			s.st.KeyCheck = old
			return err
		}
		s.v4 = true
		return nil
	}
	return s.write(s.v4)
}

func (s *Store) write(v4 bool) error {
	s.st.MAC, s.st.MAC2, s.st.MAC3, s.st.MAC4, s.st.MAC5 = s.mac(), nil, nil, nil, nil
	if s.st.hasNewer() {
		s.st.MAC2 = s.mac2()
	}
	if s.st.hasNewer3() {
		s.st.MAC3 = s.mac3()
	}
	if v4 || s.st.hasNewer4() {
		s.st.MAC4 = s.mac4()
	}
	if s.st.Alerts != nil {
		s.st.MAC5 = s.mac5()
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
	IP          string      // where the agent is, for a canary's log
}

// PutResult says what an agent's put replaced.
type PutResult struct {
	Existed     bool // there was a value before
	WasVariable bool // ...and it was a variable
	// Canary: the key is a canary, and this write was logged as a touch.
	Canary *CanaryTouch
}

// AgentPut stores a value for an agent token. Everything is checked under
// one lock: ErrExists when there's a value and Overwrite isn't set,
// ErrReadOnly for a read-only token, ErrNotOwner when an add token tries to
// replace a value (or fill a request) another token or the admin made.
func (s *Store) AgentPut(ns, name string, value []byte, p AgentPut) (PutResult, error) {
	var d, u string
	if p.Description != nil {
		d = *p.Description
	}
	if p.Usage != nil {
		u = *p.Usage
	}
	if err := CheckAgentText(d, u); err != nil {
		return PutResult{}, err
	}
	return s.putValue(ns, name, value, nil, p.Overwrite, &p)
}

func (s *Store) putValue(ns, name string, value []byte, meta *Meta, overwrite bool, ap *AgentPut) (PutResult, error) {
	if !ValidName(ns) {
		return PutResult{}, ErrBadName
	}
	if !ValidSecretName(name) {
		return PutResult{}, ErrBadSecret
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	snap := s.st.clone()
	res, err := s.putLocked(ns, name, value, meta, nil, overwrite, ap)
	if err != nil {
		s.st = snap
		return res, err
	}
	return res, s.commit(snap)
}

// putLocked is putValue's work, with s.mu held and no commit. kind, when
// set, is the new value's kind (meta and ap set it otherwise). On error
// the caller restores its snapshot.
func (s *Store) putLocked(ns, name string, value []byte, meta *Meta, kind *bool, overwrite bool, ap *AgentPut) (PutResult, error) {
	var res PutResult
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
	sec.Batch = nil // a filled request is no longer part of a batch
	if meta != nil {
		applyMeta(sec, *meta)
	}
	if kind != nil {
		sec.Variable = *kind
	}
	if ap == nil && sec.creator() != "" {
		// The admin's value now: the add token that made the key can't
		// replace it any more.
		e := sec.ext()
		e.CreatedBy = ""
		sec.setExt(e)
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
	if ap == nil {
		sec.dropCanaryIfVariable()
	} else if sec.Canary {
		// An agent can't tell a canary, so it can't unmark one either: a
		// kind change by an agent leaves the flag, and the write is a
		// touch like a read.
		h := s.touchCanary(sec, ap.Token.Name, ap.IP, "write", now)
		res.Canary = &h
	}
	action := "created"
	if res.Existed {
		action = "replaced"
	}
	s.record(Event{Namespace: ns, Name: name, Action: action, Actor: actor, Detail: sec.Kind()})
	return res, nil
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

// sameText compares text from a form with stored text, ignoring the CRLF
// line ends browsers send for a textarea.
func sameText(a, b string) bool {
	return strings.ReplaceAll(a, "\r\n", "\n") == strings.ReplaceAll(b, "\r\n", "\n")
}

func applyMeta(sec *Secret, m Meta) {
	sec.Description, sec.Usage, sec.Expires, sec.Variable = m.Description, m.Usage, m.Expires, m.Variable
	sec.dropCanaryIfVariable()
}

// dropCanaryIfVariable clears the canary flag on a variable: only secrets
// can be canaries (a variable's reads aren't even recorded).
func (sec *Secret) dropCanaryIfVariable() {
	if sec.Variable {
		sec.Canary = false
	}
}

// UpdateMeta changes description, usage and expiry without touching the
// value. An agent-written description stays marked as the agent's unless
// the admin changes its text.
func (s *Store) UpdateMeta(ns, name string, m Meta) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	snap := s.st.clone()
	sec, ok := s.st.Secrets[key(ns, name)]
	if !ok {
		return ErrNotFound
	}
	same := sameText(sec.Description, m.Description) && sameText(sec.Usage, m.Usage)
	applyMeta(sec, m)
	sec.UpdatedAt = s.now().UTC()
	if !same && sec.Ext != nil && sec.Ext.DescriptionBy != "" {
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
	if err := CheckAgentText(description, usage); err != nil {
		return err
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
		open := 0
		for _, other := range s.st.Secrets {
			if other.Pending && other.RequestedBy == by {
				open++
			}
		}
		if open >= maxRequestsPerToken {
			return ErrLimit
		}
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
	sec.dropCanaryIfVariable()
	sec.New, sec.AckedBy, sec.UpdatedAt = true, nil, s.now().UTC()
	s.record(Event{Namespace: ns, Name: name, Action: "rolled back", Actor: "admin", Detail: sec.Kind()})
	return s.commit(snap)
}

// Reveal decrypts a value for the admin and, for a secret, records the
// read. variable is the kind read under the same lock as the value, so
// callers deciding whether to audit or mask can't be fooled by a kind
// change in between.
func (s *Store) Reveal(ns, name, by string) (value []byte, variable bool, err error) {
	return s.reveal(ns, name, by, "")
}

// AgentReveal is Reveal for the token named tok, using it from ip. It also
// marks the value as picked up by that token: no longer new to it, and no
// longer "new" on the admin's page. Reading a canary records the read
// (hit is set) in the same write as any other read, so it takes as long,
// and returns the value as usual.
func (s *Store) AgentReveal(ns, name, tok, ip string) (value []byte, variable bool, hit *CanaryTouch, err error) {
	return s.revealHit(ns, name, tok, tok, ip)
}

func (s *Store) reveal(ns, name, by, tok string) (value []byte, variable bool, err error) {
	value, variable, _, err = s.revealHit(ns, name, by, tok, "")
	return value, variable, err
}

func (s *Store) revealHit(ns, name, by, tok, ip string) (value []byte, variable bool, hit *CanaryTouch, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	snap := s.st.clone()
	sec, ok := s.st.Secrets[key(ns, name)]
	if !ok {
		return nil, false, nil, ErrNotFound
	}
	if len(sec.Value) == 0 {
		return nil, sec.Variable, nil, ErrNoValue
	}
	pt, err := s.open(sec.Value, aad(ns, name, "value"))
	if err != nil {
		return nil, false, nil, fmt.Errorf("decrypting %s: %w", key(ns, name), err)
	}
	changed := false
	if tok != "" && (sec.New || !slices.Contains(sec.AckedBy, tok)) {
		sec.New = false
		if !slices.Contains(sec.AckedBy, tok) {
			sec.AckedBy = append(slices.Clone(sec.AckedBy), tok)
		}
		changed = true
	}
	now := s.now().UTC()
	if !sec.Variable {
		sec.LastReadAt, sec.LastReadBy = &now, by
		changed = true
	}
	// A canary an agent made a variable is still a canary (see putLocked).
	if sec.Canary && tok != "" {
		h := s.touchCanary(sec, tok, ip, "read", now)
		hit = &h
		changed = true
	}
	if changed {
		if err := s.commit(snap); err != nil {
			return nil, false, nil, err
		}
	}
	return pt, sec.Variable, hit, nil
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

// forgetToken drops what a revoked token left attached to its name, so a
// new token given the same name starts clean: its acks; its ownership of
// the keys it created (else the new token could replace them under add
// permission); its pending requests (they become the admin's, so no
// token can change or fill them under add permission); its pending notes
// and proposals (never approved, and nobody left to stand behind them);
// and its open flags, which stay for the admin but are marked so they
// don't count against, or block, the new token. Call with s.mu held.
func (s *Store) forgetToken(tok string) {
	for _, sec := range s.st.Secrets {
		if i := slices.Index(sec.AckedBy, tok); i >= 0 {
			sec.AckedBy = slices.Delete(slices.Clone(sec.AckedBy), i, i+1)
		}
		if sec.Pending && sec.RequestedBy == tok {
			sec.RequestedBy = ""
			if sec.Batch != nil && sec.Batch.Label != "" {
				b := *sec.Batch
				b.Label = "" // its proposal, like the description
				sec.Batch = &b
			}
		}
		if sec.Ext == nil {
			continue
		}
		e := sec.ext()
		if e.CreatedBy == tok {
			e.CreatedBy = ""
		}
		if e.Proposal != nil && e.Proposal.By == tok {
			e.Proposal = nil
		}
		e.Notes = slices.DeleteFunc(e.Notes, func(n Note) bool { return n.Pending && n.By == tok })
		for i := range e.Flags { // a clone
			if e.Flags[i].By == tok {
				e.Flags[i].TokenRevoked = true
			}
		}
		sec.setExt(e)
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
	return s.createToken(name, namespaces, perm, sources, nil, 0)
}

// CreatePairedToken is CreateTokenExpiring for pairing: unless Collected
// is called with the token by collectBy, RevokeUncollected deletes it.
func (s *Store) CreatePairedToken(name string, namespaces []string, perm Permission, sources []string, collectBy time.Time, days int) (string, error) {
	if err := CheckLifetime(days); err != nil {
		return "", err
	}
	return s.createToken(name, namespaces, perm, sources, &collectBy, days)
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

func (s *Store) createToken(name string, namespaces []string, perm Permission, sources []string, collectBy *time.Time, days int) (string, error) {
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
	t := s.st.Tokens[name]
	t.ExpiresAt, t.Lifetime = expiryFor(days, t.CreatedAt), days
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
			s.forgetToken(name)
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
	s.forgetToken(name)
	return s.commit(snap)
}

// LookupToken finds the token matching plain, checks it may be used from
// ip, and records its use. Use from a disallowed address returns the token
// (so it can be named in the log) with ErrSource, and isn't recorded as
// use. An expired token returns the token with ErrExpired, isn't recorded
// as use either, and must be refused exactly like an unknown one. Last-used
// is persisted at most once a minute, to avoid a disk write per request.
func (s *Store) LookupToken(plain, ip string) (Token, error) {
	return s.lookupToken(plain, ip, false)
}

// LookupTokenForRenewal is LookupToken for the renewal endpoints only: it
// also accepts a token that expired less than RenewalGrace ago (Expired
// reports it), so the agent can ask for the token to be extended, and a
// token whose renewal was approved (Rotation set), until its collect
// window ends, so the agent can collect its replacement. Sources are
// still checked. Never use it for anything else.
func (s *Store) LookupTokenForRenewal(plain, ip string) (Token, error) {
	return s.lookupToken(plain, ip, true)
}

func (s *Store) lookupToken(plain, ip string, renewal bool) (Token, error) {
	if !strings.HasPrefix(plain, TokenPrefix) {
		return Token{}, ErrNotFound
	}
	h := hashToken(plain)
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	for _, t := range s.st.Tokens {
		if t.Hash != h {
			continue
		}
		expired := t.Expired(now)
		if expired && (!renewal || !now.Before(t.ExpiresAt.Add(RenewalGrace))) {
			return *t, ErrExpired
		}
		if !t.AllowsFrom(ip) {
			return *t, ErrSource
		}
		if expired {
			return *t, nil // in the grace window: not use, not recorded
		}
		at := now.UTC()
		t.LastUsedFrom = ip
		save := false
		if t.Rotation != nil {
			// The renewed token's first use: the old one, and the sealed
			// copy kept for collecting it again, are no longer needed.
			snap := s.st.clone()
			t.Rotation = nil
			t.LastUsedAt = &at
			if err := s.commit(snap); err != nil {
				return Token{}, err
			}
		} else if t.LastUsedAt == nil || at.Sub(*t.LastUsedAt) > time.Minute {
			t.LastUsedAt = &at
			save = true
		}
		if save {
			_ = s.save()
		}
		return *t, nil
	}
	// An old token replaced by a renewal: it may only collect the new one,
	// from an allowed address, until the window closes.
	for _, t := range s.st.Tokens {
		if t.Rotation == nil || subtle.ConstantTimeCompare([]byte(t.Rotation.OldHash), []byte(h)) != 1 {
			continue
		}
		switch {
		case !now.Before(t.Rotation.CollectBy):
			return *t, ErrExpired
		case !renewal:
			return *t, ErrRotated
		case !t.AllowsFrom(ip):
			return *t, ErrSource
		}
		return *t, nil // Rotation set: authenticated as the old token
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

// SetTokenNamespaces replaces the namespaces a token may read.
func (s *Store) SetTokenNamespaces(name string, namespaces []string) error {
	if len(namespaces) == 0 {
		return ErrBadName
	}
	for _, n := range namespaces {
		if !ValidName(n) {
			return ErrBadName
		}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	snap := s.st.clone()
	t, ok := s.st.Tokens[name]
	if !ok {
		return ErrNotFound
	}
	t.Namespaces = append([]string(nil), namespaces...)
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
