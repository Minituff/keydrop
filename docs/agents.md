# Using keydrop from an AI agent

The CLI is the whole integration: an agent runs shell commands, so it runs
`keydrop`. This page covers instructions to give the agent, plus optional
hooks for Claude Code.

## Instructions to give the agent

Paste something like this into `CLAUDE.md` / `AGENTS.md`:

```markdown
## Secrets (keydrop)
API keys live in keydrop, not in files or chat. You can use them but you
never need to see them.
- If keydrop says there's no token, run `keydrop pair --url URL` in the
  background, send the user the link and code it prints, and wait for it
  to finish. Never ask the user to paste a token.
- Never ask the user to paste a secret into chat. If you need one, run
  `keydrop request NAME --desc "what it's for, which scopes, how long it should
  last"`, send the user the link it prints, then `keydrop wait NAME`.
- Use secrets only through `keydrop run`. `-e NAME` sets `$NAME` for one
  command: `keydrop run -e GITHUB_PAT -- sh -c 'curl -H "Authorization: Bearer $GITHUB_PAT" …'`
  (single-quote the script so the child expands the variable, not your
  shell). `-e VAR=NAME` sets it under another name.
- `keydrop secrets` / `keydrop info NAME` show what exists and what each key
  is for. Follow the description: it says what to do with the key.
- Non-secret settings (URLs, account IDs) are variables: `keydrop vars`
  lists them with values, `keydrop get NAME` prints one, and `run -e NAME`
  takes them like secrets.
- Changes to keys show up in `keydrop history`. If a key stops working,
  `keydrop status NAME expired` (or `revoked`, `leaked`) tells other agents,
  and `keydrop flag NAME "reason"` asks the human to look.
- Never run `keydrop get --raw`, `env`, `printenv`, or anything else that
  prints a value. If output shows `[keydrop:NAME]`, that's the mask working.
  Don't try to recover the value.
```

## Several agents on one machine

Agents running as the same user share that machine's token: pair once.
To tell them apart in the log, give each its own `KEYDROP_AGENT`, for
example in each agent's service environment:

```sh
KEYDROP_AGENT=claude   # Claude Code
KEYDROP_AGENT=codex    # Codex
```

The log then shows `token:homelab-box (claude)`. It's a label for reading
the log, not a permission.

## Claude Code hooks

In `.claude/settings.json`:

```json
{
  "hooks": {
    "SessionStart": [
      { "hooks": [ { "type": "command", "command": "keydrop history --since 72h --quiet" } ] }
    ],
    "PreToolUse": [
      {
        "matcher": "Bash",
        "hooks": [ { "type": "command", "command": "keydrop-guard" } ] }
    ]
  }
}
```

- **SessionStart:** whatever `keydrop history` prints becomes context at the
  start of the session: the keys created, replaced or marked in the last
  three days, with who and when. `--quiet` prints nothing when there's
  nothing. (`keydrop inbox --quiet`, the old hook, still works for one
  release: it runs `history --since 72h` and prints a deprecation note.)
- **PreToolUse guard:** a small script that blocks commands that would print
  a value. For example, `keydrop-guard`:

  ```sh
  #!/bin/sh
  # Reads the tool call JSON on stdin; exit 2 blocks it and shows stderr to Claude.
  cmd=$(python3 -c 'import json,sys; print(json.load(sys.stdin)["tool_input"].get("command",""))')
  case "$cmd" in
    *"keydrop get"*"--raw"*|*"keydrop"*"--no-mask"*)
      echo "Blocked: this would print a secret value. Use keydrop run instead." >&2; exit 2 ;;
  esac
  exit 0
  ```

The guard is a guard-rail for honest mistakes, not a security boundary (see
the threat model in the README).

## Health checks

```sh
keydrop expiring --days 14 --check || notify "keys expiring soon: $(keydrop expiring --days 14)"
```

Only names and dates are printed, so this is safe to send to a chat channel.
