package main

import (
	"strings"
	"testing"
	"time"
)

func TestGuardCommand(t *testing.T) {
	blocked := map[string]string{
		// get --raw, in the spellings Go's flag package takes.
		"keydrop get X --raw":             reasonRaw,
		"keydrop get --raw X":             reasonRaw,
		"keydrop get X -raw":              reasonRaw,
		"keydrop get X --raw=true":        reasonRaw,
		"keydrop get X -raw=1":            reasonRaw,
		"keydrop get X --to-file f --raw": reasonRaw,
		"keydrop get 'X' \"--raw\"":       reasonRaw,
		"keydrop get X --raw 2>/dev/null": reasonRaw,
		"keydrop \\\n  get X \\\n  --raw": reasonRaw,
		// By name or path, after assignments and wrappers.
		"/usr/local/bin/keydrop get X --raw":     reasonRaw,
		"./keydrop get X --raw":                  reasonRaw,
		"~/.local/bin/keydrop get X --raw":       reasonRaw,
		"C:/tools/KEYDROP.EXE get X --raw":       reasonRaw,
		"KEYDROP_AGENT=x keydrop get X --raw":    reasonRaw,
		"sudo -E keydrop get X --raw":            reasonRaw,
		"env -i A=1 keydrop get X --raw":         reasonRaw,
		"command keydrop get X --raw":            reasonRaw,
		"exec keydrop get X --raw":               reasonRaw,
		"nohup keydrop get X --raw &":            reasonRaw,
		"time keydrop get X --raw":               reasonRaw,
		"sudo env A=1 nohup keydrop get X --raw": reasonRaw,
		// Anywhere in a compound command.
		"true && keydrop get X --raw":                     reasonRaw,
		"false || keydrop get X --raw":                    reasonRaw,
		"cd /tmp;keydrop get X --raw":                     reasonRaw,
		"echo a | keydrop get X --raw":                    reasonRaw,
		"sleep 1 & keydrop get X --raw":                   reasonRaw,
		"echo a\nkeydrop get X --raw":                     reasonRaw,
		"(cd /tmp && keydrop get X --raw)":                reasonRaw,
		"echo $(keydrop get X --raw)":                     reasonRaw,
		"T=\"$(keydrop get X --raw)\" make":               reasonRaw,
		"echo `keydrop get X --raw`":                      reasonRaw,
		"echo $(echo $(keydrop get X --raw))":             reasonRaw,
		"sh -c 'keydrop get X --raw'":                     reasonRaw,
		"bash -lc \"cd /; keydrop get X --raw\"":          reasonRaw,
		"zsh -c 'sh -c \"keydrop get X --raw\"'":          reasonRaw,
		"keydrop run -e X -- keydrop get Y --raw":         reasonRaw,
		"keydrop run -e X -- sh -c 'keydrop get Y --raw'": reasonRaw,

		// --no-mask among keydrop's own flags.
		"keydrop run --no-mask -e X -- make":          reasonNoMask,
		"keydrop run -e X -no-mask cmd":               reasonNoMask,
		"keydrop run --no-mask=true --stdin X -- cmd": reasonNoMask,
		"sh -c 'keydrop run --no-mask -e X -- make'":  reasonNoMask,

		// keydrop run -- env / printenv.
		"keydrop run -e X -- env":                       reasonDump,
		"keydrop run -e X -- env -0":                    reasonDump,
		"keydrop run -e X -- /usr/bin/env":              reasonDump,
		"keydrop run -e X -- sudo -E env":               reasonDump,
		"keydrop run -e X -- printenv":                  reasonDump,
		"keydrop run -e X -- printenv X":                reasonDump,
		"keydrop run --env=X printenv":                  reasonDump,
		"keydrop run -e X -- sh -c 'env'":               reasonDump,
		"keydrop run -e X -- bash -c 'printenv | sort'": reasonDump,
		"x=$(keydrop run -e X -- printenv X)":           reasonDump,
	}
	allowed := []string{
		"", "ls -la", "keydrop", "keydrop secrets", "keydrop get X",
		"keydrop get X --to-file /tmp/x",
		"keydrop get X --to-file --raw", // --raw is the file's name
		"keydrop get X --raw=false",
		"keydrop get X --raw=maybe", // keydrop refuses the flag
		"keydrop get X -- --raw",    // a name, not a flag
		"keydrop get X ---raw",      // not a flag Go accepts
		"keydropper get X --raw",
		"keydrop run -e X -- make deploy",
		"keydrop run -e GITHUB_PAT -- sh -c 'curl -H \"Authorization: Bearer $GITHUB_PAT\" https://api.github.com/user'",
		"keydrop run --stdin X -- docker login -u me --password-stdin ghcr.io",
		"keydrop run -e X -- grep --no-mask file", // the command's flag, not run's
		"keydrop run -e X -- cmd --raw",
		"keydrop run -e X --no-mask=false -- make",
		"keydrop run -e X -- env FOO=1 make",
		"keydrop history --since 72h --quiet",
		"keydrop guard --command 'keydrop get X --raw'",
		"env", "printenv", "sh -c printenv", // nothing of keydrop's in them
		// Mentions that aren't invocations.
		"echo \"never use keydrop get --raw\"",
		"echo keydrop get X --raw",
		"grep -- --no-mask docs/",
		"git commit -m 'guard: block keydrop get --raw'",
		"keydrop note X 'never use get --raw'",
		// Known limits (docs/agent-setup.md): these pass.
		"eval keydrop get X --raw",
		"if keydrop get X --raw; then :; fi",
		"keydrop run -e X -- sh -c 'echo $X'",
		"$KD get X --raw",
		// Unbalanced input doesn't panic.
		"echo 'open", "echo \"open $(", "echo `", "echo $", "echo \\",
	}
	for cmd, want := range blocked {
		if got, reason := guardCommand(cmd); !got || reason != want {
			t.Errorf("guardCommand(%q) = %v, %q; want %q", cmd, got, reason, want)
		}
	}
	for _, cmd := range allowed {
		if got, reason := guardCommand(cmd); got {
			t.Errorf("guardCommand(%q) blocked (%q); want allowed", cmd, reason)
		}
	}
}

func TestGuardReasons(t *testing.T) {
	const pasted = "sk-test-FAKE0123456789abcdef"
	for _, cmd := range []string{
		"keydrop get " + pasted + " --raw",
		"keydrop run --no-mask -e " + pasted + " -- make",
		"keydrop run -e " + pasted + " -- env",
	} {
		blocked, reason := guardCommand(cmd)
		// One fixed line that says what to do, never the command, which
		// could hold a pasted value.
		if !blocked || strings.Contains(reason, pasted) || strings.ContainsAny(reason, "\r\n") || !strings.HasPrefix(reason, "Blocked: ") {
			t.Errorf("%q: blocked %v, reason %q", cmd, blocked, reason)
		}
	}
}

func TestGuardDeepAndLarge(t *testing.T) {
	// $(...) and sh -c share one depth cap, so even at the input cap the
	// work stays linear.
	for _, unit := range []string{"sh -c \"$(sh -c '", "$(", "bash -c \"sh -c \\\"sh -c '$(", "`sh -c \"", "a; ", "keydrop run -e X -- sh -c \""} {
		start := time.Now()
		guardCommand(strings.Repeat(unit, maxGuardInput/len(unit)))
		if d := time.Since(start); d > 20*time.Second {
			t.Errorf("%q repeated to 1 MiB took %v", unit, d)
		}
	}
}

func TestHookCommand(t *testing.T) {
	big := `{"tool_name":"Bash","tool_input":{"command":"keydrop get X --raw","description":"` + strings.Repeat("a", maxGuardInput) + `"}}`
	cases := map[string]string{
		`{"tool_name":"Bash","tool_input":{"command":"keydrop get X --raw"}}`:                                 "keydrop get X --raw",
		`{"hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"ls","description":"x"}}`: "ls",
		`{"tool_name":"Write","tool_input":{"command":"keydrop get X --raw"}}`:                                "",
		`{"tool_name":"Bash","tool_input":{"command":["keydrop","get"]}}`:                                     "",
		`{"tool_name":"Bash","tool_input":"keydrop get X --raw"}`:                                             "",
		`{"tool_name":"Bash","tool_input":{"command":"keydrop get X --raw"`:                                   "", // truncated
		`not json`: "",
		``:         "",
		big:        "",
	}
	for in, want := range cases {
		if got := hookCommand(strings.NewReader(in)); got != want {
			t.Errorf("hookCommand(%.80s) = %q, want %q", in, got, want)
		}
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
		if err := cmdGuard(args); err == nil || asExit(err, &ec) {
			t.Errorf("cmdGuard(%q) = %v, want a plain error (exit 1)", args, err)
		}
	}
}
