package server

import (
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"strings"

	"github.com/minituff/keydrop/internal/store"
)

// ---- groups on the dashboard ----

// groupSection is one group's entries on the dashboard: its name, palette
// colour, whether it's an auto group, and the entries (with their value
// for variables).
type groupSection struct {
	store.GroupRef
	Rows  []varRow
	Count int
}

// nsSection is one namespace's groups.
type nsSection struct {
	Namespace string
	Groups    []groupSection
}

// arrange puts entries under namespace and group headings.
func (s *Server) arrange(secs []store.Secret, assign map[string]store.GroupRef, values bool) []nsSection {
	var out []nsSection
	for _, gv := range store.ArrangeGroups(secs, assign) {
		if len(out) == 0 || out[len(out)-1].Namespace != gv.Namespace {
			out = append(out, nsSection{Namespace: gv.Namespace})
		}
		g := groupSection{GroupRef: gv.GroupRef, Count: len(gv.Entries)}
		for _, sec := range gv.Entries {
			row := varRow{Secret: sec}
			if values && sec.Variable {
				v, _ := s.store.VariableValue(sec.Namespace, sec.Name)
				row.Value = string(v)
			}
			g.Rows = append(g.Rows, row)
		}
		ns := &out[len(out)-1]
		ns.Groups = append(ns.Groups, g)
	}
	return out
}

// requestCard is one card of requests on the dashboard: a batch, or a
// single request.
type requestCard struct {
	ID        string // the HTML id, batch-<id> for a batch
	Namespace string
	Requests  []store.Secret
	// Label is the group name the agent proposed: agent-written, never
	// applied unless the admin ticks the box.
	Label   string
	LabelBy string
	// GroupName prefills the group box: an existing group the label (or
	// the names' shared prefix) matches, else the label or prefix.
	GroupName     string
	ExistingGroup bool
	// Color is the palette name for the card's left border: the existing
	// group's, else one picked from the prefilled name.
	Color string
	// AskedBy is who made the first request, "" if that token is gone.
	AskedBy string
	// Title heads the card. Never the agent's label: that's shown only
	// marked as agent-written (and in the group box the admin must tick).
	Title string
}

func (s *Server) requestCards(pending []store.Secret) []requestCard {
	var cards []requestCard
	idx := map[string]int{}
	for _, sec := range pending {
		k, id := sec.Ref(), "request-"+sec.Namespace+"-"+sec.Name
		if sec.Batch != nil && sec.Batch.ID != "" {
			k, id = sec.Namespace+"\x00"+sec.Batch.ID, "batch-"+sec.Batch.ID
		}
		i, ok := idx[k]
		if !ok {
			i = len(cards)
			idx[k] = i
			cards = append(cards, requestCard{ID: id, Namespace: sec.Namespace})
		}
		c := &cards[i]
		c.Requests = append(c.Requests, sec)
		if len(c.Requests) == 1 {
			c.AskedBy = sec.RequestedBy
		}
		if c.Label == "" && sec.Batch != nil && sec.Batch.Label != "" {
			c.Label, c.LabelBy = sec.Batch.Label, sec.RequestedBy
		}
	}
	for i := range cards {
		c := &cards[i]
		prefix := sharedPrefix(c.Requests)
		c.Title = c.Namespace
		if len(c.Requests) == 1 {
			c.Title = c.Requests[0].Ref()
		} else if prefix != "" {
			c.Title = c.Namespace + ": " + prefix // from key names, not agent prose
		}
		guess := c.Label
		if guess == "" {
			guess = prefix
		}
		if guess == "" {
			continue
		}
		if g, ok := s.store.FindGroup(c.Namespace, guess); ok {
			c.GroupName, c.ExistingGroup, c.Color = g.Name, true, g.Color
			if len(c.Requests) > 1 {
				c.Title = g.Name
			}
		} else if c.Label != "" || len(c.Requests) > 1 {
			c.GroupName, c.Color = guess, store.AutoColor(guess)
		}
	}
	return cards
}

// sharedPrefix is the part before the first '_' that every name shares.
func sharedPrefix(secs []store.Secret) string {
	p := ""
	for i, sec := range secs {
		q, _, ok := strings.Cut(sec.Name, "_")
		if !ok || q == "" || (i > 0 && q != p) {
			return ""
		}
		p = q
	}
	return p
}

// filledFlash is the flash after a request card is saved: the names
// saved, from the redirect's n=, checked so a link can't inject text.
func filledFlash(r *http.Request) string {
	q := r.URL.Query()
	if q.Get("msg") != "filled" {
		return ""
	}
	names := strings.Split(q.Get("n"), ",")
	if len(names) == 0 || len(names) > store.MaxBatch {
		return "Saved."
	}
	for _, n := range names {
		if !store.ValidSecretName(n) {
			return "Saved."
		}
	}
	msg := "Saved " + strings.Join(names, ", ") + "."
	if g := q.Get("g"); g == "1" {
		msg += " They're in the group you picked."
	}
	return msg
}

// handleFillRequests saves a request card: the values typed for each
// name, or a pasted file split by name. It's all or nothing; an empty
// field leaves that request open.
func (s *Server) handleFillRequests(w http.ResponseWriter, r *http.Request, _ string, se *session) {
	fail := func(msg string) { s.renderInbox(w, r, se, http.StatusBadRequest, msg) }
	ns := r.PostFormValue("namespace")
	names := r.PostForm["name"]
	if !store.ValidName(ns) || len(names) == 0 || len(names) > store.MaxBatch {
		fail("That form is out of date. Reload the page and try again.")
		return
	}
	for i, n := range names {
		if !store.ValidSecretName(n) || slices.Contains(names[:i], n) {
			fail("That form is out of date. Reload the page and try again.")
			return
		}
	}
	values := map[string][]byte{}
	for _, n := range names {
		v, hint := readValue(r, "value."+n)
		if hint != "" {
			fail(n + ": " + hint + " Nothing was saved.")
			return
		}
		if len(v) > 0 {
			values[n] = v
		}
	}
	if paste := r.PostFormValue("paste"); strings.TrimSpace(paste) != "" {
		if len(values) > 0 {
			fail("Use either the pasted file or the separate fields, not both. Nothing was saved.")
			return
		}
		lines, err := parsePaste(paste)
		if err == nil {
			var m map[string]string
			if m, err = mapPaste(lines, names); err == nil {
				for n, v := range m {
					values[n] = []byte(v)
				}
			}
		}
		if err != nil {
			fail("Pasted file: " + err.Error())
			return
		}
	}
	if len(values) == 0 {
		fail("Nothing to save: fill in at least one value, or paste the file.")
		return
	}
	groupName := ""
	if r.PostFormValue("group") == "yes" {
		var err error
		if groupName, err = store.CheckGroupName(r.PostFormValue("groupname")); err != nil {
			fail("Group: " + err.Error() + ". Nothing was saved.")
			return
		}
	}
	var fills []store.Fill
	for _, n := range names { // in the form's order
		if v, ok := values[n]; ok {
			fills = append(fills, store.Fill{Name: n, Value: v, Variable: r.PostFormValue("kind."+n) == "variable"})
		}
	}
	existed := false
	if groupName != "" {
		_, existed = s.store.FindGroup(ns, groupName)
	}
	filled, g, err := s.store.FillRequests(ns, fills, groupName)
	switch {
	case errors.Is(err, store.ErrNotPending):
		s.renderInbox(w, r, se, http.StatusConflict, err.Error()+". Someone may have filled or deleted it; nothing was saved. Reload the page.")
		return
	case err != nil:
		fail(err.Error() + ". Nothing was saved.")
		return
	}
	var saved []string
	for _, f := range filled {
		ref := ns + "/" + f.Name
		detail := "fulfilled request from a revoked token"
		if f.RequestedBy != "" {
			detail = "fulfilled request from " + f.RequestedBy
		}
		if f.Variable {
			detail += ", as a variable"
		}
		s.event(r, "admin", "secret.set", ref, detail)
		saved = append(saved, f.Name)
	}
	refs := make([]string, len(saved))
	for i, n := range saved {
		refs[i] = ns + "/" + n
	}
	s.noteDups(se, refs...)
	q := url.Values{"msg": {"filled"}, "n": {strings.Join(saved, ",")}}
	if g != nil {
		if !existed {
			s.event(r, "admin", "group.create", ns+"/"+g.Slug, g.Name)
		}
		for _, n := range saved {
			s.event(r, "admin", "group.assign", ns+"/"+n, g.Name)
		}
		q.Set("g", "1")
	}
	http.Redirect(w, r, "/?"+q.Encode(), http.StatusSeeOther)
}

// ---- the groups page ----

type groupsNS struct {
	Namespace string
	Groups    []groupRow
	Auto      []groupRow
}

type groupRow struct {
	store.GroupRef
	Count int
}

func (s *Server) handleGroups(w http.ResponseWriter, r *http.Request, _ string, se *session) {
	s.renderGroups(w, r, se, http.StatusOK, "")
}

func (s *Server) renderGroups(w http.ResponseWriter, r *http.Request, se *session, status int, errMsg string) {
	assign := s.store.GroupAssignments()
	counts := map[store.GroupRef]int{}
	for _, ref := range assign {
		counts[ref]++
	}
	var out []groupsNS
	at := map[string]int{}
	section := func(ns string) *groupsNS {
		i, ok := at[ns]
		if !ok {
			i = len(out)
			at[ns] = i
			out = append(out, groupsNS{Namespace: ns})
		}
		return &out[i]
	}
	for _, g := range s.store.Groups("") {
		ref := store.GroupRef{Namespace: g.Namespace, Slug: g.Slug, Name: g.Name, Color: g.Color, Description: g.Description}
		sec := section(g.Namespace)
		sec.Groups = append(sec.Groups, groupRow{ref, counts[ref]})
	}
	var autos []store.GroupRef
	for ref := range counts {
		if ref.Auto {
			autos = append(autos, ref)
		}
	}
	slices.SortFunc(autos, func(a, b store.GroupRef) int {
		return strings.Compare(a.Namespace+"\x00"+a.Name, b.Namespace+"\x00"+b.Name)
	})
	for _, ref := range autos {
		sec := section(ref.Namespace)
		sec.Auto = append(sec.Auto, groupRow{ref, counts[ref]})
	}
	slices.SortStableFunc(out, func(a, b groupsNS) int { return strings.Compare(a.Namespace, b.Namespace) })
	nss := s.store.Namespaces()
	def := ""
	if len(nss) == 1 {
		def = nss[0]
	}
	s.render(w, r, "groups", status, se, page{
		"Title": "Groups", "Sections": out, "Palette": store.Palette, "AutoOn": s.store.AutoGroups(),
		"Namespaces": nss, "DefaultNS": def, "Error": errMsg,
	})
}

func groupError(err error) string {
	switch {
	case errors.Is(err, store.ErrExists):
		return "There's already a group with that name in this namespace. Pick another name."
	case errors.Is(err, store.ErrNotFound):
		return "There's no such group. Reload the page."
	case errors.Is(err, store.ErrLimit):
		return "This namespace has too many groups. Delete some first."
	case errors.Is(err, store.ErrBadText):
		return "The description must be one line, without control or invisible formatting characters."
	}
	return err.Error() + "."
}

func (s *Server) handleCreateGroup(w http.ResponseWriter, r *http.Request, _ string, se *session) {
	ns, _ := formNamespace(r, s.store.Namespaces())
	if !store.ValidName(ns) {
		s.renderGroups(w, r, se, http.StatusBadRequest, "Namespace: lowercase letters, digits, '.', '_' and '-' only.")
		return
	}
	g, err := s.store.CreateGroup(ns, r.PostFormValue("name"), r.PostFormValue("color"), r.PostFormValue("description"))
	if err != nil {
		s.renderGroups(w, r, se, http.StatusBadRequest, groupError(err))
		return
	}
	s.event(r, "admin", "group.create", ns+"/"+g.Slug, g.Name)
	http.Redirect(w, r, "/groups?msg=groupsaved", http.StatusSeeOther)
}

func (s *Server) handleUpdateGroup(w http.ResponseWriter, r *http.Request, _ string, se *session) {
	ns, slug := r.PathValue("ns"), r.PathValue("slug")
	old, ok := s.store.GetGroup(ns, slug)
	if !ok {
		s.renderGroups(w, r, se, http.StatusNotFound, groupError(store.ErrNotFound))
		return
	}
	if err := s.store.UpdateGroup(ns, slug, r.PostFormValue("name"), r.PostFormValue("color"), r.PostFormValue("description")); err != nil {
		s.renderGroups(w, r, se, http.StatusBadRequest, groupError(err))
		return
	}
	now, _ := s.store.GetGroup(ns, slug)
	detail := now.Name
	if old.Name != now.Name {
		detail = "renamed from " + old.Name + " to " + now.Name
	}
	if old.Color != now.Color {
		detail += ", colour " + now.Color
	}
	s.event(r, "admin", "group.update", ns+"/"+slug, detail)
	http.Redirect(w, r, "/groups?msg=groupsaved", http.StatusSeeOther)
}

func (s *Server) handleDeleteGroup(w http.ResponseWriter, r *http.Request, _ string, se *session) {
	ns, slug := r.PathValue("ns"), r.PathValue("slug")
	if r.PostFormValue("confirm") != "yes" {
		s.renderGroups(w, r, se, http.StatusBadRequest, "Tick the box to confirm.")
		return
	}
	g, _ := s.store.GetGroup(ns, slug)
	n, err := s.store.DeleteGroup(ns, slug)
	if err != nil {
		s.renderGroups(w, r, se, http.StatusNotFound, groupError(err))
		return
	}
	s.event(r, "admin", "group.delete", ns+"/"+slug, fmt.Sprintf("%s, %d entries ungrouped", g.Name, n))
	http.Redirect(w, r, "/groups?msg=groupdel", http.StatusSeeOther)
}

// handlePromoteGroup makes an auto group a real one.
func (s *Server) handlePromoteGroup(w http.ResponseWriter, r *http.Request, _ string, se *session) {
	ns, prefix := r.PostFormValue("namespace"), r.PostFormValue("prefix")
	g, n, err := s.store.PromoteAutoGroup(ns, prefix)
	if err != nil {
		s.renderGroups(w, r, se, http.StatusBadRequest, groupError(err))
		return
	}
	s.event(r, "admin", "group.create", ns+"/"+g.Slug, fmt.Sprintf("%s, from the auto group (%d entries)", g.Name, n))
	http.Redirect(w, r, "/groups?msg=groupsaved", http.StatusSeeOther)
}

// handleSetEntryGroup puts an entry in a group, or in none.
func (s *Server) handleSetEntryGroup(w http.ResponseWriter, r *http.Request, _ string, se *session) {
	ns, name, slug := r.PathValue("ns"), r.PathValue("name"), r.PostFormValue("group")
	old, ok := s.store.GetSecret(ns, name)
	if !ok {
		s.message(w, r, http.StatusNotFound, "Not found", "There's no secret called "+ns+"/"+name+".")
		return
	}
	switch err := s.store.SetEntryGroup(ns, name, slug); {
	case errors.Is(err, store.ErrNoGroup):
		s.renderSecret(w, r, se, http.StatusBadRequest, "There's no such group. Reload the page.")
		return
	case err != nil:
		s.renderSecret(w, r, se, http.StatusInternalServerError, err.Error())
		return
	}
	if old.Group != slug {
		if slug == "" {
			s.event(r, "admin", "group.unassign", ns+"/"+name, old.Group)
		} else {
			g, _ := s.store.GetGroup(ns, slug)
			s.event(r, "admin", "group.assign", ns+"/"+name, g.Name)
		}
	}
	s.back(w, r, "grouped")
}

func (s *Server) handleAutoGroups(w http.ResponseWriter, r *http.Request, _ string, se *session) {
	on := r.PostFormValue("on") == "yes"
	if err := s.store.SetAutoGroups(on); err != nil {
		s.renderSettings(w, r, se, http.StatusInternalServerError, err.Error())
		return
	}
	detail := "off"
	if on {
		detail = "on"
	}
	s.event(r, "admin", "settings.autogroups", "", detail)
	http.Redirect(w, r, "/settings?msg=autogroups", http.StatusSeeOther)
}
