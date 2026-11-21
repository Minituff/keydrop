# Examples

Ready-to-copy files for using keydrop with an agent. They call the
`keydrop` CLI, so they need nothing else installed and stay in step with
it when `keydrop upgrade` runs.

- [`claude-code/settings.json`](claude-code/settings.json): Claude Code
  hooks. Merge its `hooks` into your project's `.claude/settings.json` (or
  `~/.claude/settings.json` for every project).
  - `SessionStart` runs `keydrop history --since 72h --quiet`, so each
    session starts knowing which keys changed lately.
  - `PreToolUse` runs `keydrop guard` before every shell command and blocks
    one that would print a secret's value (`keydrop get --raw`,
    `--no-mask`, `keydrop run -- env`), telling Claude what to do instead.

  If `keydrop` isn't on the `PATH` Claude Code runs hooks with, use its
  full path, such as `~/.local/bin/keydrop`. Check first that
  `keydrop guard --command ls` exits 0: an older CLI without the guard
  exits 2, which as a hook blocks every shell command.

- [`claude-code/mcp.json`](claude-code/mcp.json): registers `keydrop mcp`
  as an MCP server. Copy it to your project's `.mcp.json`. It's optional:
  the CLI does everything, and the MCP tools only make listing, checking
  and requesting keys discoverable. No tool returns a secret's value.

What the guard catches and what it doesn't, and why it's a guard-rail
rather than a security boundary:
[docs/agent-setup.md](../docs/agent-setup.md#claude-code-hooks).
