# Pairing an agent by hand

0. Install the CLI. The server hands out its own build, so the CLI is always
   the server's version. On Linux and macOS (amd64 and arm64) the machine
   needs nothing but `curl`. The exact command is on the **Agents** page and
   in the server log:
   ```sh
   curl -fsSk --pinnedpubkey 'sha256//…' https://192.168.1.50:8443/install.sh | sh
   ```
   `-k` skips the usual certificate check and `--pinnedpubkey` replaces it
   with a check of keydrop's own key, so a different server can't hand you
   a different binary. Behind a proxy with a real certificate it's just
   `curl -fsS https://secrets.example.com/install.sh | sh`. The script
   picks the build with `uname`, checks it against `SHA256SUMS`, and
   installs to `~/.local/bin` (`KEYDROP_INSTALL_DIR` to change). For
   Windows, see [below](#windows).
1. On the agent's machine, as the agent's user (or let the agent run it):
   ```sh
   keydrop pair --url https://192.168.1.50:8443 --pin sha256:…
   ```
   It prints a link and a short code, then waits.
2. Open the link (logged in to keydrop). The page shows the code and the
   address the request came from. Check the code matches, then choose the
   agent's name, its namespaces (tick existing ones, or type new ones), its
   permission (read, add or write), where it's allowed from (pre-filled with
   that address), how often it gets a new token, and whether it may upgrade
   its own CLI. Approve.
3. `keydrop pair` picks up the token within a few seconds and writes
   `~/.config/keydrop/{url,token,pin}` with mode 600. The token never
   passes through the chat or the page. If it was interrupted, running
   `keydrop pair` again carries on waiting.
4. Use it:
   ```sh
   keydrop history                                 # what changed lately?
   keydrop secrets                                 # what keys exist (no values)
   keydrop vars                                    # non-secret settings, with values
   keydrop run -e CLOUDFLARE_API_TOKEN -- terraform apply   # sets $CLOUDFLARE_API_TOKEN
   keydrop run -e TOKEN=CLOUDFLARE_API_TOKEN -- sh -c 'curl -H "Authorization: Bearer $TOKEN" …'
   keydrop status CLOUDFLARE_API_TOKEN expired     # tell everyone it stopped working
   keydrop flag CLOUDFLARE_API_TOKEN "401 since this morning"   # ask the admin to look
   keydrop request GITHUB_PAT --desc "Fine-grained PAT for org/repo, contents:read, 90 days"
   keydrop wait GITHUB_PAT
   keydrop request EXAMPLE_API_KEY EXAMPLE_API_SECRET --group Router --desc "Router API key pair, read-only"
   ```

`-e NAME` sets `$NAME`; `-e VAR=NAME` sets `$VAR` instead. Repeat `-e` for
several secrets. Values only ever go into the command's environment, never
its arguments, because arguments are visible in `/proc/<pid>/cmdline` to
other processes. Inside `sh -c '…'`, use single quotes so the variable is
expanded by the child, not by your shell.

Secret names look like environment variables: capital letters, digits and
`_`, not starting with a digit. The web page upper-cases what you type; the
CLI and API don't, and refuse a lower-case name.

`keydrop get NAME` prints a variable and refuses a secret. For a file (a
kubeconfig, a PEM): `keydrop get NAME --to-file PATH` writes it with mode
600 (with `--force` it replaces the file, and a symlink there is replaced
rather than followed). `keydrop get NAME --raw` prints a secret, which
defeats the point; it exists for the rare pipe that needs it.

`keydrop run` removes every `KEYDROP_*` variable from the command's
environment, but the command runs as the same user and could read the
token file: `run` keeps the token out of the way, it isn't a sandbox.

To store a variable from the CLI: `echo https://… | keydrop put API_URL --var`.
This needs a write token. A variable an agent stores can be at most 2,000
characters on one line, and other agents see it labelled as untrusted text
(`get` and `run -e` pass the value on unchanged and say so on stderr).
`put` takes text up to 60 KiB; base64 a binary value first.

To migrate an existing `.env` (needs a token with add or write access):
`keydrop import .secrets.env --dry-run`, then without `--dry-run`. Comment
lines above a key become its description, and each key keeps its name
(keys that aren't upper-case are skipped). Values are never printed, and a
file with a multi-line value is refused whole: use `keydrop put` for that
one. Rotate
anything that sat in plaintext for long. `--vars` imports every key as a
variable instead, for a file of plain settings (write tokens only).

Each token can hold up to 500 keys and 8 MiB of values that it stored. Keys
you've saved a value for yourself stop counting.

**Allowed sources.** Each token can be limited to addresses or ranges
(`10.0.0.5`, `10.0.1.0/24`). Use from anywhere else is refused (HTTP 403)
and logged as `token.denied`, so a token copied off the machine doesn't
work elsewhere. Pairing fills in the address the request came from; edit
it under **Agents**. Empty means anywhere. Behind a reverse proxy, set
`KEYDROP_TRUSTED_PROXIES` so keydrop sees the agent's real address.

**Several agents, one token.** Agents on one machine (Claude Code and
Codex, say) can share its token. Set `KEYDROP_AGENT=claude` in each one's
environment and the log shows `token:my-box (claude)`. It's a label,
not an identity: anything with the token can set it.

Without pairing, you can still create a token by hand under **Agents** and
paste it into `keydrop login --url URL`.

## Windows

`install.sh` is for Linux and macOS. On Windows, download the build under
**Other systems** on the **Agents → Add an agent** page and check it against
`SHA256SUMS`. Releases on GitHub carry every build too. The CLI keeps its
files in `%USERPROFILE%\.config\keydrop`, and works from there like on any
other system, except that Windows has no file modes, so there's no warning
about a token file other users could read. What protects the file is its
folder's permissions, and your user profile is private by default, so keep the
token there: don't point `KEYDROP_TOKEN_FILE` at a shared folder.

`keydrop --version` shows the build on any system. keydrop tells you, at most
once a day, if it doesn't match the server's.

## What to read next

The rules to give the agent (for its `CLAUDE.md` or `AGENTS.md`), a
session-start history hook and a guard against `--raw` are in
[docs/agent-setup.md](agent-setup.md).
[docs/design_doc.md](design_doc.md) explains how keydrop is built and
why.
