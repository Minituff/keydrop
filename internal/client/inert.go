package client

import (
	"fmt"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"
)

// Inert makes text from the server safe to print: control characters
// (terminal escapes included), bidirectional overrides and other
// non-printing characters are shown as \x.. / \u.... escapes, so they're
// visible and inert. multiline keeps newlines; tabs become spaces.
func Inert(s string, multiline bool) string {
	var b strings.Builder
	for len(s) > 0 {
		r, size := utf8.DecodeRuneInString(s)
		switch {
		case r == utf8.RuneError && size == 1: // not UTF-8
			fmt.Fprintf(&b, "\\x%02x", s[0])
		case r == '\n' && multiline:
			b.WriteByte('\n')
		case r == '\t':
			b.WriteByte(' ')
		case r < 0x80 && !strconv.IsPrint(r):
			fmt.Fprintf(&b, "\\x%02x", r)
		case !strconv.IsPrint(r) || unicode.In(r, unicode.Variation_Selector, unicode.Other_Default_Ignorable_Code_Point):
			fmt.Fprintf(&b, "\\u%04x", r)
		default:
			b.WriteRune(r)
		}
		s = s[size:]
	}
	return b.String()
}

// maxServerMessage is how much of an error a server (or a proxy in front
// of it) sent is kept, in characters.
const maxServerMessage = 300

// serverMessage is an error body made fit to print as part of one line:
// inert, on one line, and short. A hostile server or a proxy's error page
// can't print lines that look like keydrop's own, or bury them.
func serverMessage(s string) string {
	s = Inert(strings.TrimSpace(s), false)
	if utf8.RuneCountInString(s) <= maxServerMessage {
		return s
	}
	n := 0
	for i := range s {
		if n == maxServerMessage {
			return s[:i] + "…"
		}
		n++
	}
	return s
}
