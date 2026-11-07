package server

import (
	"net/http"
	"slices"
	"strings"
)

// newNamespace is the namespace picker's "+ New namespace" choice. A
// namespace is only ever made by picking it, so a typo in the list can't
// quietly create one.
const newNamespace = "+new"

// formNamespace reads the namespace picker. isNew says the admin chose
// "+ New namespace" and typed a name that didn't exist yet.
func formNamespace(r *http.Request, existing []string) (ns string, isNew bool) {
	ns = strings.TrimSpace(r.PostFormValue("namespace"))
	if ns != newNamespace {
		return ns, false
	}
	// Lower-cased: a phone keyboard capitalises the first letter.
	ns = strings.ToLower(strings.TrimSpace(r.PostFormValue("new_namespace")))
	return ns, !slices.Contains(existing, ns)
}

// formNamespaces reads a multi-namespace picker: the ticked existing ones
// (ns) plus any typed in the new-namespaces field (namespaces), in order,
// without repeats.
func formNamespaces(r *http.Request) []string {
	var out []string
	add := func(n string) {
		if n != "" && !slices.Contains(out, n) {
			out = append(out, n)
		}
	}
	for _, n := range r.PostForm["ns"] {
		add(strings.TrimSpace(n))
	}
	for _, n := range splitList(r.PostFormValue("namespaces")) {
		add(strings.ToLower(n))
	}
	return out
}

// nsOpt is one checkbox of a multi-namespace picker.
type nsOpt struct {
	Name string
	On   bool
}

// nsOpts is the checkboxes for all namespaces, ticked where selected. A
// selected namespace that doesn't exist yet is listed too, so a form shown
// again after an error keeps it.
func nsOpts(all, selected []string) []nsOpt {
	names := slices.Clone(all)
	for _, n := range selected {
		if !slices.Contains(names, n) {
			names = append(names, n)
		}
	}
	slices.Sort(names)
	out := make([]nsOpt, len(names))
	for i, n := range names {
		out[i] = nsOpt{n, slices.Contains(selected, n) || (len(selected) == 0 && len(all) == 1)}
	}
	return out
}
