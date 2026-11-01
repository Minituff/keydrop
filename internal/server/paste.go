package server

import (
	"fmt"
	"regexp"
	"sort"
	"strings"
)

// Pasting a downloaded credentials file. Values never appear in errors:
// they name the line number and the requested names only. Not even the
// line's key is echoed, as a mis-pasted line may be all value.

var pasteKeyRE = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_.-]{0,63}$`)

type pasteLine struct {
	n          int // 1-based line number
	key, value string
}

// parsePaste reads key=value, key: value and export KEY=value lines.
// Blank lines and # comments are skipped. Values may be quoted.
func parsePaste(text string) ([]pasteLine, error) {
	var out []pasteLine
	for i, raw := range strings.Split(text, "\n") {
		n := i + 1
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if rest, ok := strings.CutPrefix(line, "export"); ok && rest != "" && (rest[0] == ' ' || rest[0] == '\t') {
			line = strings.TrimSpace(rest)
		}
		cut := strings.IndexAny(line, "=:")
		if cut < 0 {
			return nil, fmt.Errorf("line %d isn't key=value or key: value. Fix or remove that line; nothing was saved.", n)
		}
		key, value := strings.TrimSpace(line[:cut]), strings.TrimSpace(line[cut+1:])
		if !pasteKeyRE.MatchString(key) {
			return nil, fmt.Errorf("line %d doesn't start with a key name. Fix or remove that line; nothing was saved.", n)
		}
		if value != "" && (value[0] == '"' || value[0] == '\'') {
			// Quoted: the value is what's between the quotes, and only a
			// # comment may follow. Anything else (no closing quote, an
			// escaped quote, text after it) is refused rather than saved
			// with stray quotes or a comment in it.
			end := strings.IndexByte(value[1:], value[0])
			if end < 0 {
				return nil, fmt.Errorf("line %d has an opening quote but no closing one. Fix that line; nothing was saved.", n)
			}
			rest := strings.TrimSpace(value[end+2:])
			if rest != "" && !strings.HasPrefix(rest, "#") {
				return nil, fmt.Errorf("line %d has text after its closing quote. Fix that line; nothing was saved.", n)
			}
			value = value[1 : end+1]
		} else if strings.Contains(value, " #") || strings.Contains(value, "\t#") {
			// A comment, or part of the value? Don't guess.
			return nil, fmt.Errorf("line %d has a # after a space. If it starts a comment, remove the comment; if it's part of the value, put the value in quotes; nothing was saved.", n)
		}
		if value == "" {
			return nil, fmt.Errorf("line %d has no value. Fix or remove that line; nothing was saved.", n)
		}
		out = append(out, pasteLine{n: n, key: key, value: value})
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("the pasted file has no key=value lines; nothing was saved.")
	}
	return out, nil
}

// lastSegment is the part of a name after its last '_'.
func lastSegment(name string) string {
	return name[strings.LastIndexByte(name, '_')+1:]
}

// mapPaste matches each line to one of the requested names: a line whose
// key is the name (ignoring case) maps to it; otherwise its key must equal
// the last '_' part of exactly one name (key= maps to EXAMPLE_API_KEY).
// It's strict: a line that maps to none or to two names, or two lines
// that map to one name, refuses the whole paste.
func mapPaste(lines []pasteLine, names []string) (map[string]string, error) {
	out := map[string]string{}
	from := map[string]int{}
	for _, l := range lines {
		var match []string
		for _, n := range names {
			if strings.EqualFold(n, l.key) {
				match = append(match, n)
			}
		}
		if len(match) == 0 {
			for _, n := range names {
				if strings.EqualFold(lastSegment(n), l.key) {
					match = append(match, n)
				}
			}
		}
		switch len(match) {
		case 0:
			return nil, fmt.Errorf("line %d doesn't match any requested name (%s). Rename its key to one of them, or remove the line; nothing was saved.", l.n, strings.Join(names, ", "))
		case 1:
		default:
			sort.Strings(match)
			return nil, fmt.Errorf("line %d could be %s. Rename its key to the full name; nothing was saved.", l.n, strings.Join(match, " or "))
		}
		if prev, ok := from[match[0]]; ok {
			return nil, fmt.Errorf("lines %d and %d both match %s. Remove one of them; nothing was saved.", prev, l.n, match[0])
		}
		from[match[0]] = l.n
		out[match[0]] = l.value
	}
	return out, nil
}

// pastedLineRE spots a value that is a whole "KEY=value" or "key: value"
// line. The '=' must be followed by something other than '=' or the
// end, so base64 padding ("abc=", "abc==") isn't mistaken for one.
var pastedLineRE = regexp.MustCompile(`^(export\s+)?[A-Za-z_][A-Za-z0-9_.-]{0,63}\s*(=[^=]|:\s)`)

const pasteHint = "This looks like you pasted the whole line. Paste only the part after key= (or key: ), or use the \"Paste the downloaded file\" box. To keep it as it is, tick \"Save it exactly as pasted\"."

// pasteMistake says why value looks like a paste mistake, or "" if it
// doesn't: a newline (unless whitespace is kept on purpose) or a leading
// KEY= / key: . The value itself is never part of the message.
func pasteMistake(value string, keepws bool) string {
	if !keepws && strings.ContainsAny(value, "\r\n") {
		return "The value has a line break. " + pasteHint
	}
	if pastedLineRE.MatchString(value) {
		return pasteHint
	}
	return ""
}
