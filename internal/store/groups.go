package store

import (
	"errors"
	"fmt"
	"hash/fnv"
	"regexp"
	"slices"
	"sort"
	"strings"
	"time"
)

// Groups, the auto-group setting and batch requests. Everything here lives
// in fields outside v2View (state.Groups, state.Settings, Secret.Group,
// Secret.Batch), covered by MAC3, so both older releases still open the
// file and drop it when they rewrite it.

var (
	ErrBadGroup = errors.New("a group needs a name of up to 64 characters, without control or invisible formatting characters")
	ErrBadColor = errors.New("pick one of the listed colours")
	ErrNoGroup  = errors.New("there's no such group in this namespace")
	ErrBatch    = errors.New("a batch request names 1 to 10 different keys")
	// ErrNotPending: a request card named a key that isn't waiting for a
	// value any more (filled or deleted meanwhile).
	ErrNotPending = errors.New("isn't waiting for a value any more")
)

const (
	// MaxGroupName bounds a group's name, and the label an agent proposes.
	MaxGroupName = 64
	// MaxGroupDescription bounds a group's one-line description.
	MaxGroupDescription = 200
	// MaxBatch is how many keys one batch request may name.
	MaxBatch = 10
	// maxGroupsPerNamespace keeps the state bounded; only the admin makes
	// groups, so it's generous.
	maxGroupsPerNamespace = 200
)

// Palette is the fixed set of group colours, by name. The UI maps each
// name to its own style; the store keeps only the name.
var Palette = []string{"red", "orange", "yellow", "green", "teal", "blue", "purple", "pink"}

// ValidColor reports whether c is a palette name.
func ValidColor(c string) bool { return slices.Contains(Palette, c) }

// AutoColor picks a palette colour from text deterministically, so an
// auto group (or a group made without choosing) keeps its colour.
func AutoColor(text string) string {
	h := fnv.New32a()
	h.Write([]byte(strings.ToUpper(text)))
	return Palette[h.Sum32()%uint32(len(Palette))]
}

// Group is a named, coloured set of entries in one namespace.
type Group struct {
	Namespace   string    `json:"namespace"`
	Slug        string    `json:"slug"`
	Name        string    `json:"name"`
	Color       string    `json:"color"`
	Description string    `json:"description,omitempty"`
	CreatedAt   time.Time `json:"created_at"`
}

// Settings are the admin's settings stored with the state.
type Settings struct {
	// AutoGroupsOff turns off grouping entries by name prefix. Stored as
	// "off" so the zero value (and a file without settings) means on.
	AutoGroupsOff bool `json:"auto_groups_off,omitempty"`
}

// RequestBatch links requests an agent made together.
type RequestBatch struct {
	ID string `json:"id"`
	// Label is the group name the agent proposed: untrusted agent text,
	// shown as such, and only used if the admin ticks the box for it.
	Label string `json:"label,omitempty"`
}

var slugRE = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,31}$`)

// ValidSlug reports whether s is usable as a group id.
func ValidSlug(s string) bool { return slugRE.MatchString(s) }

// slugify makes a group id from its name: lower-case ASCII letters and
// digits, everything else a single '-'.
func slugify(name string) string {
	var b strings.Builder
	dash := false
	for _, r := range strings.ToLower(name) {
		if r >= 'a' && r <= 'z' || r >= '0' && r <= '9' {
			b.WriteRune(r)
			dash = false
		} else if !dash && b.Len() > 0 {
			b.WriteByte('-')
			dash = true
		}
		if b.Len() >= 28 {
			break
		}
	}
	s := strings.Trim(b.String(), "-")
	if s == "" {
		s = "group"
	}
	return s
}

// CheckGroupName trims a group name (or an agent's proposed label) and
// checks it.
func CheckGroupName(name string) (string, error) {
	name = strings.TrimSpace(name)
	if name == "" || checkText(name, MaxGroupName, false) != nil {
		return "", ErrBadGroup
	}
	return name, nil
}

func checkGroupDescription(d string) (string, error) {
	d = strings.TrimSpace(d)
	return d, checkText(d, MaxGroupDescription, false)
}

// Groups lists the explicit groups of namespace ns (all of them when ns is
// empty), sorted by namespace, then name.
func (s *Store) Groups(ns string) []Group {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []Group
	for _, g := range s.st.Groups {
		if ns == "" || g.Namespace == ns {
			out = append(out, *g)
		}
	}
	sortGroups(out)
	return out
}

func sortGroups(gs []Group) {
	sort.Slice(gs, func(i, j int) bool {
		if gs[i].Namespace != gs[j].Namespace {
			return gs[i].Namespace < gs[j].Namespace
		}
		a, b := strings.ToLower(gs[i].Name), strings.ToLower(gs[j].Name)
		if a != b {
			return a < b
		}
		return gs[i].Slug < gs[j].Slug
	})
}

// GetGroup returns one group.
func (s *Store) GetGroup(ns, slug string) (Group, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	g, ok := s.st.Groups[key(ns, slug)]
	if !ok {
		return Group{}, false
	}
	return *g, true
}

// FindGroup finds a group in ns by name (ignoring case) or by the id that
// name would get. It's how a typed or agent-proposed name finds the group
// it means.
func (s *Store) FindGroup(ns, name string) (Group, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if g := s.findGroupLocked(ns, name); g != nil {
		return *g, true
	}
	return Group{}, false
}

func (s *Store) findGroupLocked(ns, name string) *Group {
	name = strings.TrimSpace(name)
	for _, g := range s.st.Groups {
		if g.Namespace == ns && strings.EqualFold(g.Name, name) {
			return g
		}
	}
	return s.st.Groups[key(ns, slugify(name))]
}

// CreateGroup makes a group in ns. color "" picks one from the name. The
// id comes from the name, with a number added if it's taken.
func (s *Store) CreateGroup(ns, name, color, description string) (Group, error) {
	if !ValidName(ns) {
		return Group{}, ErrBadName
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	snap := s.st.clone()
	g, err := s.createGroupLocked(ns, name, color, description)
	if err != nil {
		s.st = snap
		return Group{}, err
	}
	return *g, s.commit(snap)
}

func (s *Store) createGroupLocked(ns, name, color, description string) (*Group, error) {
	name, err := CheckGroupName(name)
	if err != nil {
		return nil, err
	}
	if description, err = checkGroupDescription(description); err != nil {
		return nil, err
	}
	if color == "" {
		color = AutoColor(name)
	}
	if !ValidColor(color) {
		return nil, ErrBadColor
	}
	n := 0
	for _, g := range s.st.Groups {
		if g.Namespace == ns {
			if strings.EqualFold(g.Name, name) {
				return nil, ErrExists
			}
			n++
		}
	}
	if n >= maxGroupsPerNamespace {
		return nil, ErrLimit
	}
	base := slugify(name)
	slug := base
	for i := 2; s.st.Groups[key(ns, slug)] != nil; i++ {
		slug = fmt.Sprintf("%s-%d", base, i)
	}
	if s.st.Groups == nil {
		s.st.Groups = map[string]*Group{}
	}
	g := &Group{Namespace: ns, Slug: slug, Name: name, Color: color, Description: description, CreatedAt: s.now().UTC()}
	s.st.Groups[key(ns, slug)] = g
	return g, nil
}

// UpdateGroup renames, recolours or re-describes a group. Its id stays.
func (s *Store) UpdateGroup(ns, slug, name, color, description string) error {
	name, err := CheckGroupName(name)
	if err != nil {
		return err
	}
	if description, err = checkGroupDescription(description); err != nil {
		return err
	}
	if !ValidColor(color) {
		return ErrBadColor
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	snap := s.st.clone()
	g, ok := s.st.Groups[key(ns, slug)]
	if !ok {
		return ErrNotFound
	}
	for _, o := range s.st.Groups {
		if o != g && o.Namespace == ns && strings.EqualFold(o.Name, name) {
			return ErrExists
		}
	}
	g.Name, g.Color, g.Description = name, color, description // g is the clone's
	return s.commit(snap)
}

// DeleteGroup removes a group. Its entries become ungrouped; none is
// deleted. It returns how many entries it had.
func (s *Store) DeleteGroup(ns, slug string) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	snap := s.st.clone()
	g, ok := s.st.Groups[key(ns, slug)]
	if !ok {
		return 0, ErrNotFound
	}
	n := 0
	for _, name := range s.sortedNames(ns) {
		if sec := s.st.Secrets[key(ns, name)]; sec.Group == slug {
			sec.Group = ""
			s.record(Event{Namespace: ns, Name: name, Action: "ungrouped", Actor: "admin", Detail: "group " + g.Name + " deleted"})
			n++
		}
	}
	delete(s.st.Groups, key(ns, slug))
	return n, s.commit(snap)
}

// sortedNames lists the names of ns's entries in order, so events are
// recorded in a stable order. Call with s.mu held.
func (s *Store) sortedNames(ns string) []string {
	var names []string
	for _, sec := range s.st.Secrets {
		if sec.Namespace == ns {
			names = append(names, sec.Name)
		}
	}
	sort.Strings(names)
	return names
}

// SetEntryGroup puts an entry in group slug, or in none for "".
func (s *Store) SetEntryGroup(ns, name, slug string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	snap := s.st.clone()
	if err := s.setGroupLocked(ns, name, slug); err != nil {
		s.st = snap
		return err
	}
	return s.commit(snap)
}

func (s *Store) setGroupLocked(ns, name, slug string) error {
	sec, ok := s.st.Secrets[key(ns, name)]
	if !ok {
		return ErrNotFound
	}
	if sec.Group == slug {
		return nil
	}
	if slug == "" {
		old := sec.Group
		if g := s.st.Groups[key(ns, old)]; g != nil {
			old = g.Name
		}
		sec.Group = ""
		s.record(Event{Namespace: ns, Name: name, Action: "ungrouped", Actor: "admin", Detail: "was in " + old})
		return nil
	}
	g, ok := s.st.Groups[key(ns, slug)]
	if !ok {
		return ErrNoGroup
	}
	sec.Group = slug
	s.record(Event{Namespace: ns, Name: name, Action: "grouped", Actor: "admin", Detail: "group " + g.Name})
	return nil
}

// PromoteAutoGroup makes the auto group for prefix in ns a real group
// with that name, holding the entries the auto group holds now.
func (s *Store) PromoteAutoGroup(ns, prefix string) (Group, int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	snap := s.st.clone()
	var members []string
	for _, name := range s.sortedNames(ns) {
		sec := s.st.Secrets[key(ns, name)]
		if !sec.Pending && sec.Group == "" && namePrefix(name) == prefix {
			members = append(members, name)
		}
	}
	if prefix == "" || len(members) < 2 {
		return Group{}, 0, ErrNotFound
	}
	g, err := s.createGroupLocked(ns, prefix, AutoColor(prefix), "")
	if err != nil {
		s.st = snap
		return Group{}, 0, err
	}
	for _, name := range members {
		if err := s.setGroupLocked(ns, name, g.Slug); err != nil {
			s.st = snap
			return Group{}, 0, err
		}
	}
	return *g, len(members), s.commit(snap)
}

// AutoGroups reports whether entries without a group are grouped by name
// prefix (on unless the admin turned it off).
func (s *Store) AutoGroups() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.st.Settings == nil || !s.st.Settings.AutoGroupsOff
}

// SetAutoGroups turns auto groups on or off.
func (s *Store) SetAutoGroups(on bool) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	snap := s.st.clone()
	if on {
		s.st.Settings = nil // the default: store nothing
	} else {
		s.st.Settings = &Settings{AutoGroupsOff: true}
	}
	return s.commit(snap)
}

// RequestBatch is Request for several keys at once, linked so the admin
// sees them as one card. label is a group name the agent proposes: kept
// as agent text, used only if the admin ticks the box for it. It's all or
// nothing: a name that's taken, or the open-request cap, refuses the
// whole batch, and the error names the key. It returns the batch's id.
func (s *Store) RequestBatch(ns string, names []string, description, usage, label, by string) (string, error) {
	if !ValidName(ns) {
		return "", ErrBadName
	}
	if len(names) == 0 || len(names) > MaxBatch {
		return "", ErrBatch
	}
	for i, n := range names {
		if !ValidSecretName(n) {
			return "", fmt.Errorf("%s: %w", n, ErrBadSecret)
		}
		if slices.Contains(names[:i], n) {
			return "", ErrBatch
		}
	}
	if err := CheckAgentText(description, usage); err != nil {
		return "", err
	}
	if label = strings.TrimSpace(label); label != "" {
		var err error
		if label, err = CheckGroupName(label); err != nil {
			return "", err
		}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	snap := s.st.clone()
	now := s.now().UTC()
	fresh := 0
	for _, n := range names {
		sec, ok := s.st.Secrets[key(ns, n)]
		switch {
		case !ok:
			fresh++
		case !sec.Pending:
			return "", fmt.Errorf("%s/%s: %w", ns, n, ErrExists)
		case sec.RequestedBy != by:
			return "", fmt.Errorf("%s/%s: %w", ns, n, ErrRequestedByOther)
		}
	}
	open := 0
	for _, other := range s.st.Secrets {
		if other.Pending && other.RequestedBy == by {
			open++
		}
	}
	if fresh > 0 && open+fresh > maxRequestsPerToken {
		return "", ErrLimit
	}
	id := newID()
	for _, n := range names {
		sec, ok := s.st.Secrets[key(ns, n)]
		if !ok {
			sec = &Secret{Namespace: ns, Name: n, CreatedAt: now}
			s.st.Secrets[key(ns, n)] = sec
			s.record(Event{Namespace: ns, Name: n, Action: "requested", Actor: "token:" + by})
		}
		sec.Pending, sec.RequestedBy, sec.UpdatedAt = true, by, now
		sec.Batch = &RequestBatch{ID: id, Label: label}
		e := sec.ext()
		e.Proposal = nil
		if description != "" || usage != "" {
			e.Proposal = &Proposal{Description: description, Usage: usage, By: by, At: now}
		}
		sec.setExt(e)
	}
	return id, s.commit(snap)
}

// Fill is one value the admin typed or pasted for a request.
type Fill struct {
	Name     string
	Value    []byte
	Variable bool
}

// Filled says what FillRequests saved, for the audit log.
type Filled struct {
	Name        string
	RequestedBy string // empty: the token was revoked
	Variable    bool
}

// FillRequests saves values for pending requests in ns, all or nothing,
// and puts them in the group named groupName (made if there's none by
// that name) unless it's empty. Each name must still be waiting for a
// value; otherwise nothing is saved and the error names the key.
func (s *Store) FillRequests(ns string, fills []Fill, groupName string) ([]Filled, *Group, error) {
	if !ValidName(ns) {
		return nil, nil, ErrBadName
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	snap := s.st.clone()
	fail := func(err error) ([]Filled, *Group, error) {
		s.st = snap
		return nil, nil, err
	}
	var out []Filled
	for _, f := range fills {
		sec, ok := s.st.Secrets[key(ns, f.Name)]
		if !ok || !sec.Pending || len(sec.Value) > 0 {
			return fail(fmt.Errorf("%s/%s %w", ns, f.Name, ErrNotPending))
		}
		out = append(out, Filled{Name: f.Name, RequestedBy: sec.RequestedBy, Variable: f.Variable})
		if _, err := s.putLocked(ns, f.Name, f.Value, nil, &f.Variable, false, nil); err != nil {
			return fail(err)
		}
	}
	var group *Group
	if groupName != "" {
		g := s.findGroupLocked(ns, groupName)
		if g == nil {
			var err error
			if g, err = s.createGroupLocked(ns, groupName, "", ""); err != nil {
				return fail(err)
			}
		}
		for _, f := range fills {
			if err := s.setGroupLocked(ns, f.Name, g.Slug); err != nil {
				return fail(err)
			}
		}
		cp := *g
		group = &cp
	}
	return out, group, s.commit(snap)
}

// namePrefix is the part of an entry name before its first '_', or ""
// when there's none (no '_', or a leading one).
func namePrefix(name string) string {
	p, _, ok := strings.Cut(name, "_")
	if !ok {
		return ""
	}
	return p
}

// GroupRef is the group an entry shows under: an explicit group, an auto
// group (Auto, by name prefix), or none (empty Slug: "Ungrouped").
type GroupRef struct {
	Namespace   string
	Slug        string
	Name        string
	Color       string
	Description string
	Auto        bool
}

// Ungrouped reports whether the entry is in no group.
func (g GroupRef) Ungrouped() bool { return g.Slug == "" }

// AssignGroups works out each entry's group, keyed by ref. An explicit
// group always wins. With auto on, entries without one are grouped by
// the part of the name before the first '_' when at least two of them in
// the namespace share it. Pending requests are never auto-grouped (they
// aren't listed with the rest), and don't count towards one.
func AssignGroups(entries []Secret, groups []Group, auto bool) map[string]GroupRef {
	byKey := map[string]Group{}
	for _, g := range groups {
		byKey[key(g.Namespace, g.Slug)] = g
	}
	count := map[string]int{}
	if auto {
		for _, e := range entries {
			if p := namePrefix(e.Name); p != "" && !e.Pending && !hasGroup(e, byKey) {
				count[key(e.Namespace, p)]++
			}
		}
	}
	out := make(map[string]GroupRef, len(entries))
	for _, e := range entries {
		r := GroupRef{Namespace: e.Namespace, Name: "Ungrouped"}
		if g, ok := byKey[key(e.Namespace, e.Group)]; ok && e.Group != "" {
			r = GroupRef{Namespace: g.Namespace, Slug: g.Slug, Name: g.Name, Color: g.Color, Description: g.Description}
		} else if p := namePrefix(e.Name); p != "" && !e.Pending && count[key(e.Namespace, p)] >= 2 {
			r = GroupRef{Namespace: e.Namespace, Slug: strings.ToLower(p), Name: p, Color: AutoColor(p), Auto: true}
		}
		out[e.Ref()] = r
	}
	return out
}

func hasGroup(e Secret, groups map[string]Group) bool {
	_, ok := groups[key(e.Namespace, e.Group)]
	return e.Group != "" && ok
}

// GroupView is one group's entries, for display.
type GroupView struct {
	GroupRef
	Entries []Secret
}

// ArrangeGroups puts entries under their groups (from AssignGroups):
// by namespace, then explicit groups by name, auto groups by prefix, and
// "Ungrouped" last. Entries keep their order.
func ArrangeGroups(entries []Secret, assign map[string]GroupRef) []GroupView {
	var out []GroupView
	idx := map[GroupRef]int{}
	for _, e := range entries {
		r := assign[e.Ref()]
		if r.Namespace == "" {
			r = GroupRef{Namespace: e.Namespace, Name: "Ungrouped"}
		}
		i, ok := idx[r]
		if !ok {
			i = len(out)
			idx[r] = i
			out = append(out, GroupView{GroupRef: r})
		}
		out[i].Entries = append(out[i].Entries, e)
	}
	rank := func(r GroupRef) int {
		switch {
		case r.Ungrouped():
			return 2
		case r.Auto:
			return 1
		}
		return 0
	}
	sort.SliceStable(out, func(i, j int) bool {
		a, b := out[i].GroupRef, out[j].GroupRef
		if a.Namespace != b.Namespace {
			return a.Namespace < b.Namespace
		}
		if rank(a) != rank(b) {
			return rank(a) < rank(b)
		}
		if x, y := strings.ToLower(a.Name), strings.ToLower(b.Name); x != y {
			return x < y
		}
		return a.Slug < b.Slug
	})
	return out
}

// GroupAssignments is AssignGroups over everything in the store.
func (s *Store) GroupAssignments() map[string]GroupRef {
	return AssignGroups(s.ListSecrets(nil), s.Groups(""), s.AutoGroups())
}
