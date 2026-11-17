package main

import (
	"strings"
	"testing"
	"time"
)

func TestGuardCommand(t *testing.T) {
	blocked := map[string]string{
		// get --raw, every spelling Go's flag package takes.
		"keydrop get X --raw":                       reasonRaw,
		"keydrop get --raw X":                       reasonRaw,
		"keydrop get X -raw":                        reasonRaw,
		"keydrop get X --raw=true":                  reasonRaw,
		"keydrop get X -raw=1":                      reasonRaw,
		"keydrop get ns/X --raw | base64":           reasonRaw,
		"keydrop get --to-file=f X --raw":           reasonRaw,
		"keydrop get X --to-file f --raw":           reasonRaw,
		"keydrop get 'X' \"--raw\"":                 reasonRaw,
		"keydrop get X --r\\aw":                     reasonRaw,
		"keydrop get X --raw 2>/dev/null":           reasonRaw,
		"keydrop get X --raw >out.txt 2>&1":         reasonRaw,
		"keydrop get X --raw &> log":                reasonRaw,
		"keydrop.exe get X --raw":                   reasonRaw,
		"KEYDROP.EXE get X --raw":                   reasonRaw,
		"C:/tools/keydrop.exe get X --raw":          reasonRaw,
		"/usr/local/bin/keydrop get X --raw":        reasonRaw,
		"./keydrop get X --raw":                     reasonRaw,
		"~/.local/bin/keydrop get X --raw":          reasonRaw,
		"\"$HOME/.local/bin/keydrop\" get X --raw":  reasonRaw,
		"keydrop \\\n  get X \\\n  --raw":           reasonRaw,
		"echo start\nkeydrop get X --raw\necho end": reasonRaw,
		// Prefixes.
		"sudo keydrop get X --raw":                     reasonRaw,
		"sudo -u bob -E keydrop get X --raw":           reasonRaw,
		"sudo -- keydrop get X --raw":                  reasonRaw,
		"doas -u bob keydrop get X --raw":              reasonRaw,
		"env KEYDROP_AGENT=x keydrop get X --raw":      reasonRaw,
		"env -i -u FOO A=b keydrop get X --raw":        reasonRaw,
		"KEYDROP_AGENT=x keydrop get X --raw":          reasonRaw,
		"command keydrop get X --raw":                  reasonRaw,
		"exec keydrop get X --raw":                     reasonRaw,
		"nohup keydrop get X --raw &":                  reasonRaw,
		"nice -n 5 keydrop get X --raw":                reasonRaw,
		"timeout 10 keydrop get X --raw":               reasonRaw,
		"timeout -s KILL 10s keydrop get X --raw":      reasonRaw,
		"time keydrop get X --raw":                     reasonRaw,
		"sudo env A=1 nohup keydrop get X --raw":       reasonRaw,
		"! keydrop get X --raw":                        reasonRaw,
		"if keydrop get X --raw; then echo y; fi":      reasonRaw,
		"while true; do keydrop get X --raw; done":     reasonRaw,
		"{ keydrop get X --raw; }":                     reasonRaw,
		"(keydrop get X --raw)":                        reasonRaw,
		"(cd /tmp && keydrop get X --raw)":             reasonRaw,
		"for i in 1; do keydrop get X --raw; done":     reasonRaw,
		"true && keydrop get X --raw":                  reasonRaw,
		"false || keydrop get X --raw":                 reasonRaw,
		"cd /tmp; keydrop get X --raw":                 reasonRaw,
		"echo a | keydrop get X --raw":                 reasonRaw,
		"echo a |& keydrop get X --raw":                reasonRaw,
		"sleep 1 & keydrop get X --raw":                reasonRaw,
		"cd /tmp;keydrop get X --raw":                  reasonRaw,
		"echo $(keydrop get X --raw)":                  reasonRaw,
		"echo \"$(keydrop get X --raw)\"":              reasonRaw,
		"T=$(keydrop get X --raw) curl -H \"$T\" u":    reasonRaw,
		"echo `keydrop get X --raw`":                   reasonRaw,
		"echo \"`keydrop get X --raw`\"":               reasonRaw,
		"echo $(echo $(keydrop get X --raw))":          reasonRaw,
		"diff <(keydrop get X --raw) file":             reasonRaw,
		"curl -d @<(keydrop get X --raw) url":          reasonRaw,
		"echo ${V:-$(keydrop get X --raw)}":            reasonRaw,
		"sh -c 'keydrop get X --raw'":                  reasonRaw,
		"bash -c \"keydrop get X --raw\"":              reasonRaw,
		"bash -lc 'keydrop get X --raw'":               reasonRaw,
		"bash -e -o pipefail -c 'keydrop get X --raw'": reasonRaw,
		"/bin/sh -c 'cd /tmp && keydrop get X --raw'":  reasonRaw,
		"zsh -c 'sh -c \"keydrop get X --raw\"'":       reasonRaw,
		"eval keydrop get X --raw":                     reasonRaw,
		"eval 'keydrop get X --raw'":                   reasonRaw,
		"sh <<'EOF'\nkeydrop get X --raw\nEOF":         reasonRaw,
		"bash -s <<EOF\nkeydrop get X --raw\nEOF":      reasonRaw,
		"bash <<< 'keydrop get X --raw'":               reasonRaw,
		"cat <<EOF\n$(keydrop get X --raw)\nEOF":       reasonRaw,
		"cat <<EOF >f\nhi\nEOF\nkeydrop get X --raw":   reasonRaw,
		"keydrop run -e X -- keydrop get Y --raw":      reasonRaw,

		// --no-mask.
		"keydrop run --no-mask -e X -- cmd":                      reasonNoMask,
		"keydrop run -e X --no-mask -- cmd":                      reasonNoMask,
		"keydrop run -no-mask -e X -- cmd":                       reasonNoMask,
		"keydrop run --no-mask=true -e X -- cmd":                 reasonNoMask,
		"keydrop run -e X -no-mask=T cmd":                        reasonNoMask,
		"keydrop run --stdin X --no-mask -- docker":              reasonNoMask,
		"cd x && keydrop run --no-mask -e X -- make":             reasonNoMask,
		"sh -c 'keydrop run --no-mask -e X -- make'":             reasonNoMask,
		"keydrop get X --no-mask":                                reasonNoMask,
		"/opt/keydrop run --no-mask -e X -- make":                reasonNoMask,
		"keydrop run -e X -- keydrop run --no-mask -e Y -- make": reasonNoMask,

		// keydrop run whose command prints what it was given.
		"keydrop run -e X -- env":                         reasonDump,
		"keydrop run -e X -- env -0":                      reasonDump,
		"keydrop run -e X -- /usr/bin/env":                reasonDump,
		"keydrop run -e X -- env | grep X":                reasonDump,
		"keydrop run -e X -- printenv":                    reasonDump,
		"keydrop run -e X -- printenv X":                  reasonDump,
		"keydrop run -e ns/X -- printenv X":               reasonDump,
		"keydrop run -e T=ns/X -- printenv T":             reasonDump,
		"keydrop run -e=X -- printenv X":                  reasonDump,
		"keydrop run --env X -- printenv X":               reasonDump,
		"keydrop run -e X -- sh -c env":                   reasonDump,
		"keydrop run -e X -- sh -c 'env'":                 reasonDump,
		"keydrop run -e X -- sh -c 'set'":                 reasonDump,
		"keydrop run -e X -- bash -c 'export -p'":         reasonDump,
		"keydrop run -e X -- bash -c 'export'":            reasonDump,
		"keydrop run -e X -- bash -c 'declare -p X'":      reasonDump,
		"keydrop run -e X -- bash -c 'declare -x'":        reasonDump,
		"keydrop run -e X -- bash -c 'typeset'":           reasonDump,
		"keydrop run -e X -- sh -c 'echo $X'":             reasonDump,
		"keydrop run -e X -- sh -c 'echo \"$X\"'":         reasonDump,
		"keydrop run -e X -- sh -c 'echo \"${X}\"'":       reasonDump,
		"keydrop run -e X -- sh -c 'echo ${X:0:4}'":       reasonDump,
		"keydrop run -e X -- sh -c 'echo pre$X'":          reasonDump,
		"keydrop run -e X -- sh -c \"echo \\$X\"":         reasonDump,
		"keydrop run -e X -- sh -c 'printf %s \"$X\"'":    reasonDump,
		"keydrop run -e X -- sh -c 'cd /; echo $X | xxd'": reasonDump,
		"keydrop run -e X -- sh -c 'printenv | sort'":     reasonDump,
		"keydrop run -e TOK=ns/X -- sh -c 'echo $TOK'":    reasonDump,
		"keydrop run -e A -e B -- sh -c 'echo $B'":        reasonDump,
		"keydrop run -e X -- echo $X":                     reasonDump,
		"keydrop run -e X -- env A=1 printenv X":          reasonDump,
		"keydrop run -e X -- sudo -E env":                 reasonDump,
		"keydrop run -e X -- sh -c 'sh -c \"echo \\$X\"'": reasonDump,
		"keydrop run -e X -- sh -c 'eval echo \\$X'":      reasonDump,
		"keydrop run -e X -- sh <<'EOF'\necho $X\nEOF":    reasonDump,
		"keydrop run -e X -- bash <<< 'printenv X'":       reasonDump,
		"x=$(keydrop run -e X -- printenv X)":             reasonDump,
		"sudo keydrop run -e X -- env":                    reasonDump,
	}
	allowed := []string{
		"",
		"   ",
		"ls -la",
		"keydrop",
		"keydrop secrets",
		"keydrop get X",
		"keydrop get X --to-file /tmp/x",
		"keydrop get X --to-file --raw", // --raw is the file's name
		"keydrop get X --raw=false",
		"keydrop get X -raw=0",
		"keydrop get X --raw=maybe", // keydrop refuses the flag
		"keydrop get X -- --raw",    // a name, not a flag
		"keydrop get X ---raw",      // not a flag Go accepts
		"keydrop run -e X -- make deploy",
		"keydrop run -e GITHUB_PAT -- sh -c 'curl -H \"Authorization: Bearer $GITHUB_PAT\" https://api.github.com/user'",
		"keydrop run --stdin X -- docker login -u me --password-stdin ghcr.io",
		"keydrop run -e X -- grep --no-mask file", // the command's flag, not run's
		"keydrop run -e X -- cmd --raw",
		"keydrop run -e X --no-mask=false -- make",
		"keydrop run -e X -- printenv HOME",
		"keydrop run -e X -- sh -c 'echo $HOME'",
		"keydrop run -e X -- sh -c 'echo $XY'",
		"keydrop run -e X -- sh -c \"echo '\\$X'\"", // single-quoted in the child
		"keydrop run -e X -- sh -c 'echo X'",
		"keydrop run -e X -- sh -c 'set -e; make'",
		"keydrop run -e X -- sh -c 'export FOO=1; make'",
		"keydrop run -e X -- env FOO=1 make",
		"keydrop run -e X -- bash script.sh",
		"keydrop run -e T=X -- sh -c 'echo $X'", // run set $T, not $X
		"keydrop run --stdin X -- sh -c 'echo $X'",
		"keydrop history --since 72h --quiet",
		"keydrop guard --command 'keydrop get X --raw'",
		"keydrop note X 'never use get --raw'",
		// Mentions that aren't invocations.
		"echo \"never use keydrop get --raw\"",
		"echo 'keydrop run --no-mask'",
		"echo keydrop get X --raw",
		"grep -- --no-mask docs/",
		"grep -rn 'keydrop get .* --raw' docs/",
		"rg -e '--raw' cmd/",
		"git commit -m 'guard: block keydrop get --raw'",
		"cat <<'EOF' > notes.md\nNever run `keydrop get --raw`.\nkeydrop get X --raw\nEOF",
		"cat > notes.md <<\\EOF\n$(keydrop get X --raw)\nEOF",
		"cat <<-'EOF'\n\tkeydrop get X --raw\n\tEOF\necho ok",
		"# keydrop get X --raw",
		"ls # keydrop get X --raw",
		"keydropper get X --raw",
		"mykeydrop get X --raw",
		"keydrop-old get X --raw",
		"command -v keydrop",
		"which keydrop && keydrop --version",
		"env",
		"printenv",
		"echo $X",
		"sh -c 'printenv'",
		"sh script.sh",
		"go test ./cmd/keydrop -run TestGuard",
		"echo 'unterminated",
		"echo \"unterminated $(",
		"echo ${",
		"echo $",
		"echo `",
		"cat <<EOF",
	}
	for cmd, want := range blocked {
		got, reason := guardCommand(cmd)
		if !got || reason != want {
			t.Errorf("guardCommand(%q) = %v, %q; want blocked with %q", cmd, got, reason, want)
		}
	}
	for _, cmd := range allowed {
		if got, reason := guardCommand(cmd); got {
			t.Errorf("guardCommand(%q) blocked (%q); want allowed", cmd, reason)
		}
	}
}

// The reasons are fixed text, one line each, that say what to do instead.
func TestGuardReasons(t *testing.T) {
	for _, r := range []string{reasonRaw, reasonNoMask, reasonDump} {
		if strings.ContainsAny(r, "\n\r") || !strings.HasPrefix(r, "Blocked: ") || !strings.Contains(r, "keydrop run") && !strings.Contains(r, "without --no-mask") {
			t.Errorf("reason %q: want one line starting Blocked: that says what to do", r)
		}
	}
}

func TestGuardDeepNesting(t *testing.T) {
	// Past the depth cap nothing is checked, but it must stay quick and not
	// panic.
	cmd := strings.Repeat("$(", 10000) + "keydrop get X --raw" + strings.Repeat(")", 10000)
	guardCommand(cmd)
	cmd = strings.Repeat("sh -c '", 50) + "keydrop get X --raw"
	guardCommand(cmd)
	// $(...) and sh -c share one depth budget, so mixing them at the input
	// cap stays linear rather than multiplying the work at each level.
	for _, unit := range []string{"sh -c \"$(eval '", "${", "eval ", "a; "} {
		start := time.Now()
		guardCommand(strings.Repeat(unit, maxGuardInput/len(unit)))
		if d := time.Since(start); d > 20*time.Second {
			t.Errorf("%q repeated to 1 MiB took %v", unit, d)
		}
	}
	// Within it, it's found.
	if got, _ := guardCommand("echo $(echo $(echo $(keydrop get X --raw)))"); !got {
		t.Error("three levels of $(...) not checked")
	}
}

func TestHookCommand(t *testing.T) {
	big := `{"tool_name":"Bash","tool_input":{"command":"keydrop get X --raw","description":"` + strings.Repeat("a", maxGuardInput) + `"}}`
	cases := map[string]string{
		`{"tool_name":"Bash","tool_input":{"command":"keydrop get X --raw"}}`:                                                     "keydrop get X --raw",
		`{"session_id":"s","hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"ls","description":"list"}}`: "ls",
		`{"tool_name":"Write","tool_input":{"command":"keydrop get X --raw"}}`:                                                    "",
		`{"tool_name":"Bash","tool_input":{}}`:                                                                                    "",
		`{"tool_name":"Bash","tool_input":{"command":["keydrop","get"]}}`:                                                         "",
		`{"tool_name":"Bash","tool_input":"keydrop get X --raw"}`:                                                                 "",
		`{"tool_name":"Bash"}`: "",
		`[]`:                   "",
		`null`:                 "",
		``:                     "",
		`{"tool_name":"Bash","tool_input":{"command":"keydrop get X --raw"`: "", // truncated
		`not json`: "",
		big:        "",
	}
	for in, want := range cases {
		if got := hookCommand(strings.NewReader(in)); got != want {
			name := in
			if len(name) > 100 {
				name = name[:100] + "…"
			}
			t.Errorf("hookCommand(%s) = %q, want %q", name, got, want)
		}
	}
}

// The reason never quotes the command, which could hold a pasted value.
func TestGuardReasonNeverQuotesCommand(t *testing.T) {
	const pasted = "sk-test-FAKE0123456789abcdef"
	for _, cmd := range []string{
		"keydrop get " + pasted + " --raw",
		"keydrop run --no-mask -e " + pasted + " -- make",
		"keydrop run -e " + pasted + " -- env",
		"keydrop run -e X -- sh -c 'echo $X " + pasted + "'",
	} {
		blocked, reason := guardCommand(cmd)
		if !blocked {
			t.Fatalf("%q not blocked", cmd)
		}
		if strings.Contains(reason, pasted) || strings.Contains(reason, cmd) {
			t.Errorf("reason for %q quotes the command: %q", cmd, reason)
		}
	}
}

// How Claude Code writes commit messages and PR bodies: the heredoc is
// quoted, so nothing in it runs, and its apostrophes don't end $(...).
func TestGuardCommitMessage(t *testing.T) {
	for _, cmd := range []string{
		"git commit -m \"$(cat <<'EOF'\nguard: don't let keydrop get X --raw through (it's bad)\n\nNever `keydrop get --raw`.\nEOF\n)\"",
		"gh pr create --title t --body \"$(cat <<'EOF'\n## Summary\n- blocks `keydrop run --no-mask` and keydrop get --raw\nEOF\n)\"",
	} {
		if got, _ := guardCommand(cmd); got {
			t.Errorf("blocked %q", cmd)
		}
	}
	if got, _ := guardCommand("git commit -m \"$(cat <<'EOF'\nit's fine\nEOF\n)\" && keydrop get X --raw"); !got {
		t.Error("a command after the commit's $(...) isn't checked")
	}
}

func TestCmdGuardArgs(t *testing.T) {
	if err := cmdGuard([]string{"--command", "keydrop secrets"}); err != nil {
		t.Errorf("fine command: %v", err)
	}
	var ec exitCode
	if err := cmdGuard([]string{"--command", "keydrop get X --raw"}); !asExit(err, &ec) || ec != 2 {
		t.Errorf("--raw: got %v, want exit 2", err)
	}
	// A mistyped hook must not exit 2, which would block every command.
	for _, args := range [][]string{{"--bogus"}, {"extra"}, {"--command"}} {
		err := cmdGuard(args)
		if err == nil || asExit(err, &ec) {
			t.Errorf("cmdGuard(%q) = %v, want a plain error (exit 1)", args, err)
		}
	}
}
