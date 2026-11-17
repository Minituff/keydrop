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

// keydrop guard is a Claude Code PreToolUse hook: it exits 2, with a
// one-line reason on stderr, when a shell command would print a secret's
// value into the transcript. A guard-rail for honest mistakes, not a
// security boundary: the matcher is a small tokeniser, not a shell, and
// input it can't read passes, so a broken guard never blocks every command.
// It needs no token, config or network, and never builds the API client.

const (
	maxGuardInput = 1 << 20 // bytes read from stdin
	maxGuardDepth = 4       // nesting of $(...), backticks and sh -c, together

	// The reasons are fixed text: they never quote the command, which may
	// hold a pasted value.
	reasonRaw    = "Blocked: keydrop get --raw would print a secret's value into the transcript. Use `keydrop run -e NAME -- CMD` (or `run --stdin NAME`) so the command gets the value without showing it, or `keydrop get NAME --to-file PATH` for a config file."
	reasonNoMask = "Blocked: --no-mask would let a secret's value reach the transcript unmasked. Run it without --no-mask: the command still gets the value, and keydrop hides it in the output."
	reasonDump   = "Blocked: env or printenv under keydrop run prints the values it was given. Use the value inside the command instead, e.g. `keydrop run -e NAME -- sh -c 'curl -H \"Authorization: Bearer $NAME\" URL'`."
)

func cmdGuard(args []string) error {
	fs := flag.NewFlagSet("guard", flag.ContinueOnError)
	command := fs.String("command", "", "check this shell command instead of reading Claude Code's hook JSON on stdin")
	// ContinueOnError: a mistyped hook must exit 1 (an error Claude Code
	// shows), never 2, which would block every command.
	if fs.Parse(args) != nil || fs.NArg() > 0 {
		return errors.New("usage: keydrop guard [--command 'CMD']   (a Claude Code PreToolUse hook: reads the hook's JSON on stdin)")
	}
	cmd, given := *command, false
	fs.Visit(func(*flag.Flag) { given = true })
	if !given {
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

// hookCommand returns the command of a Bash PreToolUse hook's JSON, or ""
// for anything else: another tool, no command, malformed or oversized input.
func hookCommand(r io.Reader) string {
	b, err := io.ReadAll(io.LimitReader(r, maxGuardInput+1))
	if err != nil || len(b) > maxGuardInput {
		return ""
	}
	var in struct {
		ToolName  string `json:"tool_name"`
		ToolInput struct {
			Command string `json:"command"`
		} `json:"tool_input"`
	}
	if json.Unmarshal(b, &in) != nil || in.ToolName != "Bash" {
		return "" // a command that isn't a string fails here too
	}
	return in.ToolInput.Command
}

// guardCommand reports whether a shell command would print a secret's
// value, and the reason to show.
func guardCommand(cmd string) (bool, string) {
	r := checkScript(cmd, 0, false)
	return r != "", r
}

// checkScript checks every simple command in a script. inRun is true when
// it runs under keydrop run (as sh -c 'SCRIPT').
func checkScript(script string, depth int, inRun bool) string {
	for _, c := range parseShell(script, depth) {
		if r := checkCommand(c.words, max(depth, c.depth), inRun); r != "" {
			return r
		}
	}
	return ""
}

// shCommand is one simple command's words, after quote removal, and how
// deeply nested it was found.
type shCommand struct {
	words []string
	depth int
}

// shParser splits a script into simple commands on ; & | ( ) and newlines,
// minding quotes and backslashes, and parses $(...) (to the first ")") and
// backticks into commands too. A tokeniser for common cases, not a shell.
type shParser struct {
	s        string
	i, depth int
	sub      bool // in $(...)
	out      []shCommand
}

func parseShell(s string, depth int) []shCommand {
	p := &shParser{s: s, depth: depth}
	p.run()
	return p.out
}

func (p *shParser) run() {
	var words []string
	var w strings.Builder
	inWord := false
	endWord := func() {
		if inWord {
			words, inWord = append(words, w.String()), false
			w.Reset()
		}
	}
	endCommand := func() {
		if endWord(); len(words) > 0 {
			p.out = append(p.out, shCommand{words, p.depth})
		}
		words = nil
	}
	for ; p.i < len(p.s); p.i++ {
		c := p.s[p.i]
		switch {
		case c == ' ' || c == '\t' || c == '\r':
			endWord()
			continue
		case c == '\\' && p.i+1 < len(p.s) && p.s[p.i+1] == '\n':
			p.i++ // joins lines
			continue
		case strings.IndexByte(";&|()\n", c) >= 0:
			endCommand()
			if c == ')' && p.sub {
				return // p.i stays on the ")" that ends $(...)
			}
			continue
		}
		inWord = true
		switch c {
		case '\\':
			if p.i+1 < len(p.s) {
				p.i++
				w.WriteByte(p.s[p.i])
			}
		case '\'':
			end := upto(p.s, p.i+1, '\'')
			w.WriteString(p.s[p.i+1 : end])
			p.i = end
		case '"':
			for p.i++; p.i < len(p.s) && p.s[p.i] != '"'; p.i++ {
				switch c := p.s[p.i]; {
				case c == '\\' && p.i+1 < len(p.s) && strings.IndexByte("$`\"\\", p.s[p.i+1]) >= 0:
					p.i++
					w.WriteByte(p.s[p.i])
				case c == '$' || c == '`':
					p.substitution(&w)
				default:
					w.WriteByte(c)
				}
			}
		case '$', '`':
			p.substitution(&w)
		default:
			w.WriteByte(c)
		}
	}
	endCommand()
}

// substitution parses the $(...) or `...` at p.i into commands (unless
// that's too deep), keeps it in the word as written, and leaves p.i on its
// last byte. Any other $ is just text.
func (p *shParser) substitution(w *strings.Builder) {
	start, deeper := p.i, p.depth < maxGuardDepth
	if p.s[p.i] == '`' {
		end := upto(p.s, p.i+1, '`')
		if deeper {
			inner := strings.NewReplacer("\\`", "`", "\\\\", "\\", "\\$", "$").Replace(p.s[p.i+1 : end])
			p.out = append(p.out, parseShell(inner, p.depth+1)...)
		}
		p.i = end
	} else if deeper && strings.HasPrefix(p.s[p.i:], "$(") {
		sub := &shParser{s: p.s, i: p.i + 2, depth: p.depth + 1, sub: true}
		sub.run()
		p.out = append(p.out, sub.out...)
		p.i = sub.i
	}
	w.WriteString(p.s[start:min(p.i+1, len(p.s))])
}

// checkCommand returns the reason to block one simple command, or "".
// inRun is true for the command keydrop run starts, and what it runs.
func checkCommand(words []string, depth int, inRun bool) string {
	if depth > maxGuardDepth {
		return ""
	}
	words, envOnly := stripWrappers(words)
	if inRun && envOnly {
		return reasonDump
	}
	if len(words) == 0 {
		return ""
	}
	switch commandName(words[0]) {
	case "keydrop":
		return checkKeydrop(words[1:], depth)
	case "sh", "bash", "zsh", "dash":
		// -c SCRIPT (or -lc, -ec): the first word after the options.
		k := 1
		for k < len(words) && strings.HasPrefix(words[k], "-") {
			k++
		}
		if k < len(words) && strings.Contains(strings.Join(words[1:k], " "), "c") {
			return checkScript(words[k], depth+1, inRun)
		}
	case "printenv":
		if inRun {
			return reasonDump
		}
	}
	return ""
}

// commandName is a command word's program name: the base name, lower
// case, without .exe.
func commandName(w string) string {
	w = strings.ToLower(w[strings.LastIndexAny(w, `/\`)+1:])
	return strings.TrimSuffix(w, ".exe")
}

// stripWrappers removes leading VAR=x assignments and wrappers (sudo, env,
// command, exec, nohup, time) with any words after them that start with -.
// envOnly is true when env is all there was: it prints the environment.
func stripWrappers(words []string) (rest []string, envOnly bool) {
	env := false
	for len(words) > 0 {
		if name, _, ok := strings.Cut(words[0], "="); ok && envNameRE.MatchString(name) {
			words = words[1:]
			continue
		}
		switch commandName(words[0]) {
		case "env":
			env = true
		case "sudo", "command", "exec", "nohup", "time":
			env = false
		default:
			return words, false
		}
		words = words[1:]
		for len(words) > 0 && strings.HasPrefix(words[0], "-") {
			words = words[1:]
		}
	}
	return nil, env
}

// checkKeydrop checks a keydrop command's arguments (args[0] is the
// subcommand) up to "--": get --raw, --no-mask, and what keydrop run runs.
func checkKeydrop(args []string, depth int) string {
	for k := 1; k < len(args); k++ {
		name, hasVal, on := cliFlag(args[k])
		if args[k] == "--" || name == "" && args[0] == "run" {
			if args[0] != "run" {
				return ""
			}
			if args[k] == "--" {
				k++
			}
			return checkCommand(args[k:], depth+1, true)
		}
		switch {
		case name == "raw" && args[0] == "get" && on:
			return reasonRaw
		case name == "no-mask" && on:
			return reasonNoMask
		case !hasVal && (name == "e" || name == "env" || name == "stdin" || name == "to-file"):
			k++ // its value
		}
	}
	return ""
}

// cliFlag reads a flag the way Go's flag package does: one or two dashes,
// a name, an optional =value. on is its value as a boolean; one Go can't
// parse makes keydrop fail before it prints anything, so it's false. name
// is "" for a word that isn't a flag.
func cliFlag(a string) (name string, hasVal, on bool) {
	if len(a) < 2 || a[0] != '-' {
		return "", false, false
	}
	if a = strings.TrimPrefix(a[1:], "-"); a == "" || a[0] == '-' || a[0] == '=' {
		return "", false, false
	}
	name, val, hasVal := strings.Cut(a, "=")
	b, err := strconv.ParseBool(val)
	return name, hasVal, !hasVal || err == nil && b
}

// upto is the index of the first ch in s at or after i, or len(s).
func upto(s string, i int, ch byte) int {
	if k := strings.IndexByte(s[i:], ch); k >= 0 {
		return i + k
	}
	return len(s)
}
