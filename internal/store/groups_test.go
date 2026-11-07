package store

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestGroupsCRUD(t *testing.T) {
	s, _ := Open(t.TempDir(), key32())
	s.PutValue("lab", "A", []byte("a-value"), nil)
	s.PutValue("lab", "B", []byte("b-value"), nil)
	g, err := s.CreateGroup("lab", "Cloud flare!", "blue", "dns tokens")
	if err != nil || g.Slug != "cloud-flare" || g.Color != "blue" {
		t.Fatalf("create: %+v %v", g, err)
	}
	if _, err := s.CreateGroup("lab", "CLOUD FLARE!", "", ""); !errors.Is(err, ErrExists) {
		t.Fatalf("duplicate name: %v", err)
	}
	g2, err := s.CreateGroup("lab", "cloud-flare", "", "")
	if err != nil || g2.Slug != "cloud-flare-2" || !ValidColor(g2.Color) {
		t.Fatalf("taken slug: %+v %v", g2, err)
	}
	if _, err := s.CreateGroup("other", "Cloud flare!", "", ""); err != nil {
		t.Fatalf("same name in another namespace: %v", err)
	}
	for _, bad := range []string{"", "  ", strings.Repeat("x", MaxGroupName+1), "bidi‮evil", "two\nlines"} {
		if _, err := s.CreateGroup("lab", bad, "", ""); !errors.Is(err, ErrBadGroup) {
			t.Fatalf("name %q: %v", bad, err)
		}
	}
	if _, err := s.CreateGroup("lab", "X", "chartreuse", ""); !errors.Is(err, ErrBadColor) {
		t.Fatalf("bad colour: %v", err)
	}
	must(t, s.SetEntryGroup("lab", "A", g.Slug))
	must(t, s.SetEntryGroup("lab", "B", g.Slug))
	if err := s.SetEntryGroup("lab", "A", "nope"); !errors.Is(err, ErrNoGroup) {
		t.Fatalf("unknown group: %v", err)
	}
	if err := s.SetEntryGroup("other", "A", g.Slug); !errors.Is(err, ErrNotFound) {
		t.Fatalf("unknown entry: %v", err)
	}
	must(t, s.UpdateGroup("lab", g.Slug, "Cloudflare", "green", ""))
	if got, _ := s.GetGroup("lab", g.Slug); got.Name != "Cloudflare" || got.Color != "green" || got.Slug != "cloud-flare" {
		t.Fatalf("update: %+v", got)
	}
	if err := s.UpdateGroup("lab", g.Slug, "cloud-flare", "green", ""); !errors.Is(err, ErrExists) {
		t.Fatalf("rename onto another group: %v", err)
	}
	if f, ok := s.FindGroup("lab", "cloudflare"); !ok || f.Slug != g.Slug {
		t.Fatalf("find by name: %+v", f)
	}
	n, err := s.DeleteGroup("lab", g.Slug)
	if err != nil || n != 2 {
		t.Fatalf("delete: %d %v", n, err)
	}
	for _, name := range []string{"A", "B"} {
		if sec, ok := s.GetSecret("lab", name); !ok || sec.Group != "" {
			t.Fatalf("%s after delete: %+v", name, sec)
		}
	}
	var actions []string
	for _, e := range s.History(func(e Event) bool { return e.Name == "A" }, 0) {
		actions = append(actions, e.Action)
	}
	if !strings.Contains(strings.Join(actions, ","), "grouped") || !strings.Contains(strings.Join(actions, ","), "ungrouped") {
		t.Fatalf("history for A: %v", actions)
	}
}

func TestAutoGroups(t *testing.T) {
	sec := func(ns, name, group string) Secret { return Secret{Namespace: ns, Name: name, Group: group} }
	entries := []Secret{
		sec("lab", "CF_TOKEN", ""),
		sec("lab", "CF_ZONE", ""),
		sec("lab", "CF_EXTRA", "dns"), // explicit wins, and doesn't count
		sec("lab", "GH_TOKEN", ""),    // alone: ungrouped
		sec("lab", "PLAIN", ""),
		sec("lab", "_LEAD", ""),
		sec("lab", "_LEAD2", ""),
		sec("other", "GH_PAT", ""), // other namespace doesn't count
		sec("lab", "OLD", "gone"),  // a group that doesn't exist: ungrouped
	}
	groups := []Group{{Namespace: "lab", Slug: "dns", Name: "DNS", Color: "red"}}
	got := AssignGroups(entries, groups, true)
	want := map[string]string{
		"lab/CF_TOKEN": "CF auto", "lab/CF_ZONE": "CF auto", "lab/CF_EXTRA": "DNS",
		"lab/GH_TOKEN": "Ungrouped", "lab/PLAIN": "Ungrouped", "lab/_LEAD": "Ungrouped",
		"lab/_LEAD2": "Ungrouped", "other/GH_PAT": "Ungrouped", "lab/OLD": "Ungrouped",
	}
	for ref, w := range want {
		r := got[ref]
		name := r.Name
		if r.Auto {
			name += " auto"
		}
		if name != w {
			t.Errorf("%s: %q, want %q", ref, name, w)
		}
	}
	if c := got["lab/CF_TOKEN"].Color; c != AutoColor("CF") || c != AutoColor("cf") {
		t.Fatalf("auto colour %q not stable", c)
	}
	off := AssignGroups(entries, groups, false)
	if off["lab/CF_TOKEN"].Name != "Ungrouped" || off["lab/CF_EXTRA"].Name != "DNS" {
		t.Fatalf("auto off: %+v", off)
	}
	views := ArrangeGroups(entries, got)
	var order []string
	for _, v := range views {
		order = append(order, fmt.Sprintf("%s:%s:%d", v.Namespace, v.Name, len(v.Entries)))
	}
	if g := strings.Join(order, " "); g != "lab:DNS:1 lab:CF:2 lab:Ungrouped:5 other:Ungrouped:1" {
		t.Fatalf("order: %s", g)
	}
}

func TestAutoGroupsSetting(t *testing.T) {
	dir := t.TempDir()
	s, _ := Open(dir, key32())
	if !s.AutoGroups() {
		t.Fatal("auto groups default off")
	}
	must(t, s.SetAutoGroups(false))
	s2, _ := Open(dir, key32())
	if s2.AutoGroups() {
		t.Fatal("setting not saved")
	}
	must(t, s2.SetAutoGroups(true))
	if s2.st.Settings != nil {
		t.Fatal("the default should store nothing")
	}
}

func TestPromoteAutoGroup(t *testing.T) {
	s, _ := Open(t.TempDir(), key32())
	s.PutValue("lab", "CF_A", []byte("v1-value"), nil)
	s.PutValue("lab", "CF_B", []byte("v2-value"), nil)
	s.PutValue("lab", "GH_A", []byte("v3-value"), nil)
	g, n, err := s.PromoteAutoGroup("lab", "CF")
	if err != nil || n != 2 || g.Name != "CF" || g.Color != AutoColor("CF") {
		t.Fatalf("promote: %+v %d %v", g, n, err)
	}
	if sec, _ := s.GetSecret("lab", "CF_B"); sec.Group != g.Slug {
		t.Fatalf("member: %+v", sec)
	}
	if _, _, err := s.PromoteAutoGroup("lab", "GH"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("single entry: %v", err)
	}
}

func TestRequestBatch(t *testing.T) {
	s, _ := Open(t.TempDir(), key32())
	s.PutValue("lab", "TAKEN", []byte("taken-value"), nil)
	if _, err := s.RequestBatch("lab", []string{"A", "TAKEN"}, "", "", "", "alice"); !errors.Is(err, ErrExists) || !strings.Contains(err.Error(), "TAKEN") {
		t.Fatalf("taken name: %v", err)
	}
	if _, ok := s.GetSecret("lab", "A"); ok {
		t.Fatal("a refused batch left a request")
	}
	if _, err := s.RequestBatch("lab", []string{"A", "A"}, "", "", "", "alice"); !errors.Is(err, ErrBatch) {
		t.Fatalf("repeated name: %v", err)
	}
	if _, err := s.RequestBatch("lab", make([]string, MaxBatch+1), "", "", "", "alice"); !errors.Is(err, ErrBatch) {
		t.Fatalf("too many: %v", err)
	}
	if _, err := s.RequestBatch("lab", []string{"A"}, "", "", "bad‮label", "alice"); !errors.Is(err, ErrBadGroup) {
		t.Fatalf("bad label: %v", err)
	}
	id, err := s.RequestBatch("lab", []string{"ROUTER_KEY", "ROUTER_SECRET"}, "router api", "backups", "Router", "alice")
	if err != nil {
		t.Fatal(err)
	}
	for _, n := range []string{"ROUTER_KEY", "ROUTER_SECRET"} {
		sec, _ := s.GetSecret("lab", n)
		if !sec.Pending || sec.RequestedBy != "alice" || sec.Batch == nil || sec.Batch.ID != id || sec.Batch.Label != "Router" ||
			sec.Ext == nil || sec.Ext.Proposal == nil || sec.Ext.Proposal.Description != "router api" {
			t.Fatalf("%s: %+v", n, sec)
		}
	}
	if _, err := s.RequestBatch("lab", []string{"ROUTER_KEY"}, "", "", "", "bob"); !errors.Is(err, ErrRequestedByOther) {
		t.Fatalf("another's request: %v", err)
	}
	// The cap counts every new request in the batch.
	for i := 0; i < maxRequestsPerToken-2-3; i++ {
		must(t, s.Request("lab", fmt.Sprintf("R%d", i), "", "", "alice"))
	}
	if _, err := s.RequestBatch("lab", []string{"X1", "X2", "X3", "X4"}, "", "", "", "alice"); !errors.Is(err, ErrLimit) {
		t.Fatalf("over the cap: %v", err)
	}
	if _, err := s.RequestBatch("lab", []string{"X1", "X2", "X3"}, "", "", "", "alice"); err != nil {
		t.Fatalf("up to the cap: %v", err)
	}
	// Revoking the token forgets the label it proposed.
	s.CreateToken("alice", []string{"lab"}, PermWrite, nil)
	must(t, s.RevokeToken("alice"))
	if sec, _ := s.GetSecret("lab", "ROUTER_KEY"); sec.Batch == nil || sec.Batch.Label != "" || sec.Batch.ID != id {
		t.Fatalf("after revoke: %+v", sec.Batch)
	}
}

func TestFillRequests(t *testing.T) {
	s, _ := Open(t.TempDir(), key32())
	s.RequestBatch("lab", []string{"R_KEY", "R_SECRET", "R_URL"}, "", "", "Router", "alice")
	before := s.st.clone()
	_, _, err := s.FillRequests("lab", []Fill{{Name: "R_KEY", Value: []byte("k-value")}, {Name: "NOPE", Value: []byte("x-value")}}, "Router")
	if !errors.Is(err, ErrNotPending) || !strings.Contains(err.Error(), "NOPE") {
		t.Fatalf("unknown name: %v", err)
	}
	if sec, _ := s.GetSecret("lab", "R_KEY"); !sec.Pending || len(before.Groups) != len(s.st.Groups) {
		t.Fatal("a refused fill saved something")
	}
	got, g, err := s.FillRequests("lab", []Fill{
		{Name: "R_KEY", Value: []byte("k-value")},
		{Name: "R_URL", Value: []byte("https://router.example"), Variable: true},
	}, "Router")
	if err != nil || len(got) != 2 || g == nil || g.Name != "Router" || got[0].RequestedBy != "alice" {
		t.Fatalf("fill: %+v %+v %v", got, g, err)
	}
	k, _ := s.GetSecret("lab", "R_KEY")
	u, _ := s.GetSecret("lab", "R_URL")
	r, _ := s.GetSecret("lab", "R_SECRET")
	if k.Pending || k.Variable || k.Batch != nil || k.Group != g.Slug || !u.Variable || u.Group != g.Slug {
		t.Fatalf("filled: %+v %+v", k, u)
	}
	if !r.Pending || r.Batch == nil || r.Group != "" {
		t.Fatalf("left open: %+v", r)
	}
	if v, _, _ := s.Reveal("lab", "R_KEY", ""); string(v) != "k-value" {
		t.Fatalf("value %q", v)
	}
	// An existing group is found by name, not made again.
	_, g2, err := s.FillRequests("lab", []Fill{{Name: "R_SECRET", Value: []byte("s-value")}}, "router")
	if err != nil || g2.Slug != g.Slug || len(s.Groups("lab")) != 1 {
		t.Fatalf("existing group: %+v %v", g2, err)
	}
	if _, _, err := s.FillRequests("lab", []Fill{{Name: "R_KEY", Value: []byte("again")}}, ""); !errors.Is(err, ErrNotPending) {
		t.Fatalf("filled twice: %v", err)
	}
}

// grouped makes a store using every field outside v2View.
func grouped(t *testing.T, dir string) *Store {
	t.Helper()
	s := annotated(t, dir)
	g, err := s.CreateGroup("lab", "Cloudflare", "orange", "dns")
	must(t, err)
	must(t, s.SetEntryGroup("lab", "CF", g.Slug))
	must(t, s.SetAutoGroups(false))
	if _, err := s.RequestBatch("lab", []string{"ASK_A", "ASK_B"}, "", "", "Proposed", "adder"); err != nil {
		t.Fatal(err)
	}
	return s
}

// The release before groups (265e513) parses the newer annotation fields
// but not the group ones, and checks mac and mac2 over what it parsed. A
// file this release wrote must pass both, and what it writes back (no
// group fields, no mac3) must open here.
func TestV2ReleaseReadsGroupedFile(t *testing.T) {
	dir := t.TempDir()
	grouped(t, dir)
	path := filepath.Join(dir, stateFile)
	data, _ := os.ReadFile(path)
	for _, f := range []string{`"groups"`, `"settings"`, `"group"`, `"batch"`, `"mac3"`, `"mac2"`} {
		if !strings.Contains(string(data), f) {
			t.Fatalf("no %s in the file", f)
		}
	}
	// What the v2 release parses: everything except the group fields.
	var st state
	must(t, json.Unmarshal(data, &st))
	v2 := st.v2View()
	v2.MAC, v2.MAC2 = st.MAC, st.MAC2
	s, _ := newStore(dir, key32())
	legacy := v2.legacyView()
	if !hmacEqual(v2.MAC, macOf(s.macKey, &legacy)) {
		t.Fatal("mac would not verify in the v2 release")
	}
	check := v2
	check.MAC, check.MAC2 = nil, nil
	if !hmacEqual(v2.MAC2, macOf(s.mac2Key, &check)) {
		t.Fatal("mac2 would not verify in the v2 release")
	}
	// The v2 release saves: group fields and mac3 gone.
	b, _ := json.MarshalIndent(&v2, "", "  ")
	if strings.Contains(string(b), `"groups"`) || strings.Contains(string(b), `"mac3"`) {
		t.Fatal("v2 view kept newer fields")
	}
	os.WriteFile(path, b, 0o600)
	s2, err := Open(dir, key32())
	if err != nil {
		t.Fatalf("open after the v2 release wrote it: %v", err)
	}
	if len(s2.Groups("")) != 0 || !s2.AutoGroups() {
		t.Fatal("groups survived")
	}
	if sec, _ := s2.GetSecret("lab", "CF"); sec.Ext == nil || sec.Group != "" {
		t.Fatalf("CF after the v2 release: %+v", sec)
	}
	if sec, _ := s2.GetSecret("lab", "ASK_A"); !sec.Pending || sec.Batch != nil {
		t.Fatalf("request after the v2 release: %+v", sec)
	}
}

func hmacEqual(a, b []byte) bool { return string(a) == string(b) && len(a) > 0 }

// The group fields are covered by mac3.
func TestGroupFieldsIntegrity(t *testing.T) {
	dir := t.TempDir()
	grouped(t, dir)
	path := filepath.Join(dir, stateFile)
	data, _ := os.ReadFile(path)
	try := func(name string, edit func(raw map[string]any), want error) {
		t.Helper()
		var raw map[string]any
		json.Unmarshal(data, &raw)
		edit(raw)
		b, _ := json.Marshal(raw)
		os.WriteFile(path, b, 0o600)
		_, err := Open(dir, key32())
		if !errors.Is(err, want) && !(want == nil && err == nil) {
			t.Fatalf("%s: %v, want %v", name, err, want)
		}
	}
	secrets := func(raw map[string]any) map[string]any { return raw["secrets"].(map[string]any) }
	try("group renamed", func(raw map[string]any) {
		raw["groups"].(map[string]any)["lab/cloudflare"].(map[string]any)["name"] = "Evil"
	}, ErrIntegrity)
	try("entry moved", func(raw map[string]any) {
		secrets(raw)["lab/NEW"].(map[string]any)["group"] = "cloudflare"
	}, ErrIntegrity)
	try("label changed", func(raw map[string]any) {
		secrets(raw)["lab/ASK_A"].(map[string]any)["batch"].(map[string]any)["label"] = "Other"
	}, ErrIntegrity)
	try("setting dropped", func(raw map[string]any) { delete(raw, "settings") }, ErrIntegrity)
	try("mac3 dropped", func(raw map[string]any) { delete(raw, "mac3") }, ErrIntegrity)
	try("annotation changed", func(raw map[string]any) {
		secrets(raw)["lab/CF"].(map[string]any)["ext"].(map[string]any)["notes"].([]any)[0].(map[string]any)["pending"] = false
	}, ErrIntegrity)
	try("group fields stripped", stripGroups, nil)
	try("group added without mac3", func(raw map[string]any) {
		stripGroups(raw)
		secrets(raw)["lab/CF"].(map[string]any)["group"] = "x"
	}, ErrIntegrity)
}

func stripGroups(raw map[string]any) {
	delete(raw, "mac3")
	delete(raw, "groups")
	delete(raw, "settings")
	for _, v := range raw["secrets"].(map[string]any) {
		delete(v.(map[string]any), "group")
		delete(v.(map[string]any), "batch")
	}
}
