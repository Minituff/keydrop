package server

import (
	"log"
	"net/url"
	"strings"
)

// After the admin saves a value in the web UI, it's compared with every
// other stored value (in the store, in constant time) and the admin is
// warned about any match: the same value twice is usually a paste into
// the wrong field. The save still happens. Only references go into the
// warning, never values, and agents never see it.

// noteDups records duplicate-value warnings for refs on the session, for
// the next page to show.
func (s *Server) noteDups(se *session, refs ...string) {
	d, err := s.store.Duplicates(refs)
	if err != nil {
		log.Printf("duplicate check: %v", err)
		return
	}
	if len(d) == 0 {
		return
	}
	s.mu.Lock()
	se.dups = append(se.dups, d...)
	s.mu.Unlock()
}

// takeDups returns the warnings waiting on the session and clears them, so
// each shows once.
func (s *Server) takeDups(se *session) []dupView {
	s.mu.Lock()
	d := se.dups
	se.dups = nil
	s.mu.Unlock()
	out := make([]dupView, 0, len(d))
	for _, x := range d {
		out = append(out, dupView{Ref: x.Ref, Name: nameOf(x.Ref), Other: x.Other, RefPath: secretPath(x.Ref), OtherPath: secretPath(x.Other)})
	}
	return out
}

type dupView struct {
	Ref, Name, Other   string
	RefPath, OtherPath string
}

func nameOf(ref string) string {
	_, name, _ := strings.Cut(ref, "/")
	return name
}

func secretPath(ref string) string {
	ns, name, _ := strings.Cut(ref, "/")
	return "/secret/" + url.PathEscape(ns) + "/" + url.PathEscape(name)
}
