package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
)

// keydrop guard is a Claude Code PreToolUse hook: it reads the tool call's
// JSON on stdin and exits 2, with a one-line reason on stderr, when a shell
// command would print a secret's value into the transcript. It's a CLI
// subcommand rather than a script so it reaches every agent machine with
// the CLI, at the same version, with no python or jq.
//
// It's a guard-rail for honest mistakes, not a security boundary: the
// matcher is a small shell tokeniser, not a shell, and anything it can't
// read (bad JSON, too much input, an unknown tool) is let through, so a
// broken guard never blocks every command in the session. It needs no
// token, config or network, and never builds the API client.

// maxGuardInput caps what the guard reads from stdin.
const maxGuardInput = 1 << 20

// maxGuardDepth caps nesting ($(...) in sh -c in keydrop run ...), so a
// pathological command can't make the guard slow. Deeper text isn't checked.
const maxGuardDepth = 8

// The reasons are fixed text: they never quote the command, which may hold
// a pasted value.
const (
	reasonRaw    = "Blocked: keydrop get --raw would print a secret's value into the transcript. Use `keydrop run -e NAME -- CMD` (or `run --stdin NAME`) so the command gets the value without showing it, or `keydrop get NAME --to-file PATH` for a config file."
	reasonNoMask = "Blocked: --no-mask would let a secret's value reach the transcript unmasked. Run it without --no-mask: the command still gets the value, and keydrop hides it in the output."
	reasonDump   = "Blocked: this keydrop run command prints the values it was given (env, printenv, echo $NAME). Use the value inside the command instead, e.g. `keydrop run -e NAME -- sh -c 'curl -H \"Authorization: Bearer $NAME\" URL'`."
)

func cmdGuard(args []string) error {
	fs := flag.NewFlagSet("guard", flag.ContinueOnError)
	command := fs.String("command", "", "check this shell command instead of reading Claude Code's hook JSON on stdin")
	// ContinueOnError: a mistyped hook must exit 1 (an error Claude Code
	// shows), never 2, which would block every command.
	if fs.Parse(args) != nil || fs.NArg() > 0 {
		return errors.New("usage: keydrop guard [--command 'CMD']   (a Claude Code PreToolUse hook: reads the hook's JSON on stdin)")
	}
	cmd := *command
	if !flagGiven(fs, "command") {
		if isTerminal(os.Stdin) {
			return errors.New("guard reads a Claude Code hook's JSON on stdin; to check a command by hand use keydrop guard --command 'CMD'")
		}
		cmd = hookCommand(os.Stdin)
	}
	if blocked, reason := guardCommand(cmd); blocked {
		fmt.Fprintln(os.Stderr, reason)
		return exitCode(2)
	}
	return nil
}

func flagGiven(fs *flag.FlagSet, name string) bool {
	given := false
	fs.Visit(func(f *flag.Flag) { given = given || f.Name == name })
	return given
}

// hookCommand returns the shell command in a PreToolUse hook's JSON, or ""
// for anything else: another tool, no command, malformed or oversized input.
func hookCommand(r io.Reader) string {
	b, err := io.ReadAll(io.LimitReader(r, maxGuardInput+1))
	if err != nil || len(b) > maxGuardInput {
		return ""
	}
	var in struct {
		ToolName  string `json:"tool_name"`
		ToolInput struct {
			Command any `json:"command"`
		} `json:"tool_input"`
	}
	if json.Unmarshal(b, &in) != nil || in.ToolName != "Bash" {
		return ""
	}
	s, _ := in.ToolInput.Command.(string)
	return s
}

// guardCommand reports whether a shell command would print a secret value,
// and if so the fixed reason to show. It blocks:
//
//   - keydrop get ... --raw (any spelling Go's flag package accepts);
//   - --no-mask on a keydrop command (for run, among run's own flags);
//   - keydrop run ... -- CMD where CMD dumps the environment (bare env,
//     printenv, set, export/declare/typeset with no names or -p) or
//     prints a variable run set (echo/printf $NAME), directly or in a
//     sh -c script or a heredoc fed to a shell.
//
// keydrop is recognised by name or path, after sudo, env, command, exec,
// nohup, nice, timeout and time, in any part of a compound command,
// command substitution, sh -c / bash -c string or eval. Words that are
// only arguments (echo "keydrop get --raw", grep -- --no-mask) and quoted
// heredoc bodies aren't commands, so they pass.
func guardCommand(cmd string) (bool, string) {
	for _, c := range parseShell(cmd, 0) {
		if r := checkCommand(c, nil, 0); r != "" {
			return true, r
		}
	}
	return false, ""
}

// shWord is one shell word after quote removal. vars names the parameters
// it expands ($NAME, ${NAME...}) outside single quotes; the expansions
// themselves stay in text as written.
type shWord struct {
	text string
	vars []string
}

// shCommand is one simple command: its words (redirections removed) and
// whatever heredocs and here-strings feed it.
type shCommand struct {
	words []shWord
	stdin []string
	depth int // how deeply nested it was found
}

// parseShell splits a script into simple commands, including the ones in
// command substitutions and in unquoted heredocs' substitutions. It's a
// tokeniser for the common cases, not a shell: unbalanced quotes simply run
// to the end.
func parseShell(s string, depth int) []shCommand {
	if depth > maxGuardDepth {
		return nil
	}
	p := &shParser{s: s, depth: depth}
	p.run()
	return p.out
}

// curCommand marks a heredoc whose command hasn't ended yet.
const curCommand = -2

type heredoc struct {
	cmd    int // index in out of the command it feeds, or -1 for none
	delim  string
	quoted bool
	strip  bool // <<-: leading tabs removed
}

type shParser struct {
	s      string
	i      int
	depth  int
	sub    bool // in $(...): stop at the unmatched ")"
	parens int  // open subshells
	out    []shCommand

	cur     shCommand
	word    strings.Builder
	vars    []string
	inWord  bool
	quoted  bool // the current word had quotes
	skip    int  // the next word is a redirection target (1) or heredoc delimiter (2) or here-string (3)
	strip   bool
	pending []heredoc
}

func (p *shParser) run() {
	for p.i < len(p.s) {
		c := p.s[p.i]
		switch {
		case c == ' ' || c == '\t' || c == '\r':
			p.endWord()
			p.i++
		case c == '\n':
			p.endWord()
			p.endCommand()
			p.i++
			p.readHeredocs()
		case c == ')' && p.sub && p.parens == 0:
			// The end of $(...): p.i stays on it.
			p.endWord()
			p.endCommand()
			return
		case c == ';' || c == '|' || c == '(' || c == ')':
			if c == '(' {
				p.parens++
			} else if c == ')' {
				p.parens--
			}
			p.endWord()
			p.endCommand()
			p.i++
		case c == '&':
			if p.i+1 < len(p.s) && p.s[p.i+1] == '>' { // &> and &>>
				p.endWord()
				p.i += 2
				if p.i < len(p.s) && p.s[p.i] == '>' {
					p.i++
				}
				p.skip = 1
				continue
			}
			p.endWord()
			p.endCommand()
			p.i++
		case c == '<' || c == '>':
			p.redirect()
		case c == '#' && !p.inWord:
			for p.i < len(p.s) && p.s[p.i] != '\n' {
				p.i++
			}
		case c == '\\':
			switch {
			case p.i+1 == len(p.s):
				p.i++
			case p.s[p.i+1] == '\n': // continues the line
				p.i += 2
			default:
				p.inWord, p.quoted = true, true
				p.word.WriteByte(p.s[p.i+1])
				p.i += 2
			}
		case c == '\'':
			p.inWord, p.quoted = true, true
			end := strings.IndexByte(p.s[p.i+1:], '\'')
			if end < 0 {
				p.word.WriteString(p.s[p.i+1:])
				p.i = len(p.s)
			} else {
				p.word.WriteString(p.s[p.i+1 : p.i+1+end])
				p.i += end + 2
			}
		case c == '"':
			p.inWord, p.quoted = true, true
			p.i++
			p.doubleQuoted()
		case c == '$':
			p.inWord = true
			p.dollar()
		case c == '`':
			p.inWord = true
			p.backtick()
		default:
			p.inWord = true
			p.word.WriteByte(c)
			p.i++
		}
	}
	p.endWord()
	p.endCommand()
}

func (p *shParser) endWord() {
	if !p.inWord {
		return
	}
	w := shWord{text: p.word.String(), vars: p.vars}
	switch p.skip {
	case 0:
		p.cur.words = append(p.cur.words, w)
	case 2:
		p.pending = append(p.pending, heredoc{curCommand, w.text, p.quoted, p.strip})
	case 3:
		p.cur.stdin = append(p.cur.stdin, w.text)
	}
	p.skip = 0
	p.word.Reset()
	p.vars, p.inWord, p.quoted = nil, false, false
}

func (p *shParser) endCommand() {
	idx := -1
	if len(p.cur.words) > 0 || len(p.cur.stdin) > 0 {
		idx = len(p.out)
		p.cur.depth = p.depth
		p.out = append(p.out, p.cur)
	}
	// Heredocs started in this command feed it; their bodies come later.
	for k := range p.pending {
		if p.pending[k].cmd == curCommand {
			p.pending[k].cmd = idx
		}
	}
	p.cur = shCommand{}
}

// redirect drops a redirection and the word it names (an fd number before
// it too), records a heredoc's delimiter, and treats <(...) and >(...) as
// command substitutions.
func (p *shParser) redirect() {
	if p.inWord && !p.quoted && isDigits(p.word.String()) {
		p.word.Reset()
		p.inWord = false
	}
	p.endWord()
	c := p.s[p.i]
	p.i++
	if p.i < len(p.s) && p.s[p.i] == '(' {
		p.substitution(p.i + 1)
		return
	}
	p.skip = 1
	if c == '<' && strings.HasPrefix(p.s[p.i:], "<<") {
		p.i += 2
		p.skip = 3
		return
	}
	if c == '<' && p.i < len(p.s) && p.s[p.i] == '<' {
		p.i++
		p.skip, p.strip = 2, false
		if p.i < len(p.s) && p.s[p.i] == '-' {
			p.i++
			p.strip = true
		}
		return
	}
	if p.i < len(p.s) && strings.IndexByte("<>&|", p.s[p.i]) >= 0 {
		p.i++
	}
}

func isDigits(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

// readHeredocs reads the bodies of the heredocs started on the line just
// ended. A body is the command's stdin; an unquoted one also has its
// command substitutions run, so those are parsed.
func (p *shParser) readHeredocs() {
	for _, h := range p.pending {
		var body strings.Builder
		for p.i < len(p.s) {
			end := strings.IndexByte(p.s[p.i:], '\n')
			line := p.s[p.i:]
			if end >= 0 {
				line = p.s[p.i : p.i+end]
				p.i += end + 1
			} else {
				p.i = len(p.s)
			}
			cmp := line
			if h.strip {
				cmp = strings.TrimLeft(cmp, "\t")
			}
			if strings.TrimRight(cmp, "\r") == h.delim {
				break
			}
			body.WriteString(line)
			body.WriteByte('\n')
		}
		if h.cmd >= 0 && h.cmd < len(p.out) {
			p.out[h.cmd].stdin = append(p.out[h.cmd].stdin, body.String())
		}
		if !h.quoted {
			p.scanExpansions(body.String())
		}
	}
	p.pending = nil
}

// scanExpansions parses the command substitutions in text that's expanded
// like a double-quoted string (an unquoted heredoc body).
func (p *shParser) scanExpansions(text string) {
	if p.depth >= maxGuardDepth {
		return
	}
	sub := &shParser{s: text, depth: p.depth + 1}
	for sub.i < len(sub.s) {
		switch sub.s[sub.i] {
		case '\\':
			sub.i += 2
		case '$':
			sub.dollar()
		case '`':
			sub.backtick()
		default:
			sub.i++
		}
	}
	p.out = append(p.out, sub.out...)
}

func (p *shParser) doubleQuoted() {
	for p.i < len(p.s) {
		c := p.s[p.i]
		switch c {
		case '"':
			p.i++
			return
		case '\\':
			if p.i+1 < len(p.s) {
				n := p.s[p.i+1]
				switch n {
				case '$', '`', '"', '\\':
					p.word.WriteByte(n)
				case '\n':
				default:
					p.word.WriteByte('\\')
					p.word.WriteByte(n)
				}
				p.i += 2
			} else {
				p.i++
			}
		case '$':
			p.dollar()
		case '`':
			p.backtick()
		default:
			p.word.WriteByte(c)
			p.i++
		}
	}
}

// dollar handles $NAME, ${...}, $(...), $((...)) and $'...' at p.i.
func (p *shParser) dollar() {
	start := p.i
	p.i++
	if p.i >= len(p.s) {
		p.word.WriteByte('$')
		return
	}
	switch c := p.s[p.i]; {
	case c == '(':
		p.substitution(p.i + 1)
		p.word.WriteString(p.s[start:p.i])
	case c == '{':
		var inner string
		if end := strings.IndexByte(p.s[p.i:], '}'); end >= 0 {
			inner = p.s[p.i+1 : p.i+end]
			p.i += end + 1
		} else {
			inner = p.s[p.i+1:]
			p.i = len(p.s)
		}
		if n := paramName(strings.TrimLeft(inner, "!#")); n != "" {
			p.vars = append(p.vars, n)
		}
		p.scanExpansions(inner)
		p.word.WriteString(p.s[start:p.i])
	case c == '\'':
		// $'...': ANSI-C quoting, escapes kept as written.
		p.quoted = true
		j := p.i + 1
		for j < len(p.s) && p.s[j] != '\'' {
			if p.s[j] == '\\' {
				j++
			}
			j++
		}
		p.word.WriteString(p.s[p.i+1 : min(j, len(p.s))])
		p.i = min(j+1, len(p.s))
	default:
		if n := paramName(p.s[p.i:]); n != "" {
			p.vars = append(p.vars, n)
			p.i += len(n)
		}
		p.word.WriteString(p.s[start:p.i])
	}
}

func paramName(s string) string {
	n := 0
	for n < len(s) && (s[n] == '_' || s[n] >= 'A' && s[n] <= 'Z' || s[n] >= 'a' && s[n] <= 'z' || n > 0 && s[n] >= '0' && s[n] <= '9') {
		n++
	}
	return s[:n]
}

// substitution parses the command list from open (just after "(") to its
// closing ")", the way the shell finds it (quotes and heredocs inside
// don't count), and leaves p.i after it.
func (p *shParser) substitution(open int) {
	if p.depth >= maxGuardDepth {
		// Too deep to check: just skip it.
		p.i = min(matchParen(p.s, open)+1, len(p.s))
		return
	}
	sub := &shParser{s: p.s, i: open, depth: p.depth + 1, sub: true}
	sub.run()
	p.out = append(p.out, sub.out...)
	p.i = min(sub.i+1, len(p.s))
}

// matchParen returns the index of the ")" closing a "(" just before open,
// skipping quoted text, or len(s) if there's none. It's only the fallback
// past maxGuardDepth, so it doesn't know about heredocs.
func matchParen(s string, open int) int {
	depth := 1
	for j := open; j < len(s); j++ {
		switch s[j] {
		case '\\':
			j++
		case '\'':
			k := strings.IndexByte(s[j+1:], '\'')
			if k < 0 {
				return len(s)
			}
			j += k + 1
		case '"':
			for j++; j < len(s) && s[j] != '"'; j++ {
				if s[j] == '\\' {
					j++
				}
			}
		case '(':
			depth++
		case ')':
			depth--
			if depth == 0 {
				return j
			}
		}
	}
	return len(s)
}

func (p *shParser) backtick() {
	var inner strings.Builder
	j := p.i + 1
	for j < len(p.s) && p.s[j] != '`' {
		if p.s[j] == '\\' && j+1 < len(p.s) && strings.IndexByte("`$\\", p.s[j+1]) >= 0 {
			j++
		}
		inner.WriteByte(p.s[j])
		j++
	}
	p.out = append(p.out, parseShell(inner.String(), p.depth+1)...)
	p.word.WriteString(p.s[p.i:min(j+1, len(p.s))])
	p.i = min(j+1, len(p.s))
}

// checkCommand returns the reason to block one simple command, or "".
// runEnv is set inside keydrop run's command: the variables run set there.
func checkCommand(c shCommand, runEnv map[string]bool, depth int) string {
	// One budget for both kinds of nesting ($(...) and sh -c), so the work
	// stays linear in the command's length.
	depth = max(depth, c.depth)
	if depth > maxGuardDepth {
		return ""
	}
	words, envDump := stripPrefixes(c.words)
	if runEnv != nil && envDump {
		return reasonDump
	}
	if len(words) == 0 {
		return ""
	}
	name, args := commandName(words[0].text), words[1:]
	switch name {
	case "keydrop":
		return checkKeydrop(c, args, depth)
	case "sh", "bash", "zsh", "dash", "ksh", "mksh", "ash", "yash":
		script, dashC, operand := shellScript(args)
		switch {
		case dashC:
		case operand:
			return "" // runs a script file, which isn't checked
		default:
			script = strings.Join(c.stdin, "\n") // reads the script on stdin
		}
		return checkScript(script, runEnv, depth+1)
	case "eval":
		parts := make([]string, len(args))
		for k, a := range args {
			parts[k] = a.text
		}
		return checkScript(strings.Join(parts, " "), runEnv, depth+1)
	}
	if runEnv == nil {
		return ""
	}
	// Inside keydrop run: commands that print what run put in the
	// environment.
	switch name {
	case "printenv":
		if len(args) == 0 {
			return reasonDump
		}
		for _, a := range args {
			if runEnv[a.text] {
				return reasonDump
			}
		}
	case "set":
		if len(args) == 0 {
			return reasonDump
		}
	case "export", "declare", "typeset":
		names := 0
		for _, a := range args {
			if strings.HasPrefix(a.text, "-") {
				if strings.Contains(a.text, "p") {
					return reasonDump
				}
				continue
			}
			names++
		}
		if names == 0 {
			return reasonDump
		}
	case "echo", "printf":
		for _, a := range args {
			for _, v := range a.vars {
				if runEnv[v] {
					return reasonDump
				}
			}
		}
	}
	return ""
}

func checkScript(script string, runEnv map[string]bool, depth int) string {
	for _, c := range parseShell(script, depth) {
		if r := checkCommand(c, runEnv, depth); r != "" {
			return r
		}
	}
	return ""
}

// commandName is a command word's program name: the base name, without
// .exe, lower case.
func commandName(w string) string {
	if k := strings.LastIndexAny(w, `/\`); k >= 0 {
		w = w[k+1:]
	}
	w = strings.ToLower(w)
	return strings.TrimSuffix(w, ".exe")
}

// shellScript reads a shell's arguments: the script -c runs (dashC), or
// whether it runs a script file (operand). With neither it reads stdin.
func shellScript(args []shWord) (script string, dashC, operand bool) {
	for k := 0; k < len(args); k++ {
		a := args[k].text
		switch {
		case a == "--" || a == "-":
			if k+1 < len(args) {
				return args[k+1].text, dashC, !dashC
			}
			return "", dashC, false
		case a == "-o" || a == "+o" || a == "-O" || a == "+O" || a == "--rcfile" || a == "--init-file":
			k++
		case strings.HasPrefix(a, "--"):
		case len(a) > 1 && (a[0] == '-' || a[0] == '+'):
			if a[0] == '-' && strings.Contains(a, "c") {
				dashC = true
			}
		default:
			return a, dashC, !dashC
		}
	}
	return "", dashC, false
}

// stripPrefixes removes what runs before the real command: assignments,
// reserved words and wrappers like sudo and env. envDump is true when the
// words are only env (and its options), which prints the environment.
func stripPrefixes(words []shWord) (rest []shWord, envDump bool) {
	for len(words) > 0 {
		w := words[0].text
		if isAssignment(w) {
			words = words[1:]
			continue
		}
		var valued string // options that take a value
		switch commandName(w) {
		case "!", "{", "}", "if", "then", "else", "elif", "do", "while", "until", "nohup", "builtin":
			words = words[1:]
			continue
		case "sudo":
			valued = "ughpCDrtTU"
		case "doas":
			valued = "uC"
		case "env":
			valued = "uCS"
		case "command":
			for _, a := range words[1:] {
				if a.text == "-v" || a.text == "-V" {
					return nil, false // only looks the command up
				}
			}
		case "exec":
			valued = "a"
		case "nice":
			valued = "n"
		case "time":
		case "timeout":
			valued = "sk"
		default:
			return words, false
		}
		wrapper := commandName(w)
		words = words[1:]
		for len(words) > 0 {
			a := words[0].text
			if a == "--" {
				words = words[1:]
				break
			}
			if wrapper == "env" && isAssignment(a) {
				words = words[1:]
				continue
			}
			if len(a) < 2 || a[0] != '-' {
				break
			}
			words = words[1:]
			if len(a) == 2 && strings.IndexByte(valued, a[1]) >= 0 && len(words) > 0 {
				words = words[1:]
			}
		}
		if wrapper == "timeout" && len(words) > 0 {
			words = words[1:] // the duration
		}
		if wrapper == "env" && len(words) == 0 {
			return nil, true
		}
	}
	return nil, false
}

func isAssignment(w string) bool {
	name, _, ok := strings.Cut(w, "=")
	return ok && envNameRE.MatchString(name)
}

// checkKeydrop checks the arguments of a keydrop command.
func checkKeydrop(c shCommand, args []shWord, depth int) string {
	if len(args) == 0 {
		return ""
	}
	sub, args := args[0].text, args[1:]
	switch sub {
	case "get":
		for k := 0; k < len(args); k++ {
			if args[k].text == "--" {
				break
			}
			name, val, hasVal, ok := cliFlag(args[k].text)
			if !ok {
				continue
			}
			switch name {
			case "raw":
				if boolFlag(val, hasVal) {
					return reasonRaw
				}
			case "no-mask":
				if boolFlag(val, hasVal) {
					return reasonNoMask
				}
			case "to-file":
				if !hasVal {
					k++
				}
			}
		}
	case "run":
		env := map[string]bool{}
		k := 0
		for ; k < len(args); k++ {
			a := args[k].text
			if a == "--" {
				k++
				break
			}
			name, val, hasVal, ok := cliFlag(a)
			if !ok {
				break
			}
			switch name {
			case "e", "env", "stdin":
				if !hasVal && k+1 < len(args) {
					k++
					val = args[k].text
				}
				if name != "stdin" {
					// -e NAME, ns/NAME or VAR=REF: the variable it sets.
					v, _, renamed := strings.Cut(val, "=")
					if !renamed {
						v = val[strings.LastIndexByte(val, '/')+1:]
					}
					env[v] = true
				}
			case "no-mask":
				if boolFlag(val, hasVal) {
					return reasonNoMask
				}
			}
		}
		if k < len(args) {
			child := shCommand{words: args[k:], stdin: c.stdin}
			return checkCommand(child, env, depth+1)
		}
	default:
		for _, a := range args {
			if a.text == "--" {
				break
			}
			if name, val, hasVal, ok := cliFlag(a.text); ok && name == "no-mask" && boolFlag(val, hasVal) {
				return reasonNoMask
			}
		}
	}
	return ""
}

// cliFlag splits a flag the way Go's flag package reads it: one or two
// dashes, then a name, then an optional =value.
func cliFlag(a string) (name, val string, hasVal, ok bool) {
	if len(a) < 2 || a[0] != '-' || a == "--" {
		return "", "", false, false
	}
	a = a[1:]
	if a[0] == '-' {
		a = a[1:]
	}
	if a == "" || a[0] == '-' || a[0] == '=' {
		return "", "", false, false
	}
	name, val, hasVal = strings.Cut(a, "=")
	return name, val, hasVal, true
}

// boolFlag is a boolean flag's value; one Go wouldn't parse makes keydrop
// fail before it prints anything, so it counts as false.
func boolFlag(val string, hasVal bool) bool {
	if !hasVal {
		return true
	}
	b, err := strconv.ParseBool(val)
	return err == nil && b
}
