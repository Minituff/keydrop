# keydrop: design

Why keydrop exists, how it's built and why, and what comes next. The
[README](../README.md) covers using it. This page is for working on it.

## The problem

You generate API keys, often on your phone, and need to hand them to AI
agents (Claude Code, Codex, scripts) running in a homelab. Today that
usually means one of:

- **Pasting the key into the chat.** The transcript is stored, and sent to
  the model provider.
- **A plaintext `.env` file** the agent sources. It's one `git add -A` away
  from being committed, and every tool that runs with it can print it.
- **Shell history and tool logs.** Agents log their tool output, so a
  `curl -v` that echoes an `Authorization` header ends up in the session log.

keydrop is a place to drop a key (from a phone) and a CLI that
lets an agent **use** the key without **seeing** it.

## Threat model

**Protects against accidental exposure:** values reaching chat
transcripts, tool output, shell history, git, logs or screenshots, and
plaintext at rest.

**Doesn't protect against a compromised or malicious agent.** Anything that
can use a secret can exfiltrate it. The goal is that agents never see
values during normal work, not that they can't. The README says this
plainly, and it shouldn't be watered down.

Also out of scope: multi-user teams, HA, cloud KMS, compliance features.
For those, use Vault/OpenBao or Infisical.

## Prior art (why build rather than adopt)

| | Why not |
|---|---|
| Infisical | Closest match (`infisical run`), but needs Postgres and Redis and is built for teams. |
| Vault / OpenBao | Far heavier than one person with a few agents needs. |
| Vaultwarden | No Secrets Manager API. |
| 1Password `op run` | The model for output masking, but paid and cloud-hosted. |
| SOPS / age | Encrypted files, not paste-from-phone. |

None has a paste-from-phone UI, an agent inbox/request flow, or fits in a
single small container. That gap is the reason for the project.

## Shape

One Go binary is both the server (in a container) and the agent CLI.

- **Zero third-party Go dependencies.** Everything is stdlib, including
  PBKDF2, TOTP and the self-signed certificate. The whole thing can be
  audited in an afternoon, and supply-chain risk is limited to Go itself.
  Adding a dependency should need a strong reason.
- **No JavaScript in the UI.** Server-rendered HTML forms, with the CSP set
  to forbid scripts entirely. That removes XSS as a class of bug.
- **No database.** State is one JSON file (mode 600, written atomically). A
  homelab holds tens of secrets, not thousands. It also makes backups a copy
  of one directory.
- **Distroless, non-root image** with a `healthcheck` subcommand, since
  there's no shell or curl in the image.

### Code layout

| Path | |
|---|---|
| `cmd/keydrop` | Entry point: `server`, `genkey`, `healthcheck`, and the agent commands (`agent.go`). |
| `internal/store` | State file, encryption, secrets, namespaces, tokens. |
| `internal/auth` | Password hashing, TOTP, the failed-login limiter. |
| `internal/server` | HTTP: web UI (`ui.go`, `web/`), agent API (`api.go`), pairing (`pair.go`), TLS (`tls.go`). |
| `internal/client` | API client used by the CLI, including certificate pinning. |
| `internal/mask` | Streaming output masking for `keydrop run`. |
| `internal/qr` | QR code encoder (byte mode, level M) for the authenticator setup. |
| `internal/audit` | JSONL audit log plus an in-memory ring for the UI. Fields capped at 200 bytes, rotated at 10 MiB (one old file kept), and only the last 512 KiB read at start. |

## Design decisions

### Values in the UI: shown on purpose, logged
The MVP was write-only, like GitHub Actions secrets. That was dropped
(2026-10-31): an admin can mint a token for every namespace and read any
value through the API, so hiding values from the admin protected nothing,
and the person who owns the keys should be able to check one. Instead:

- Lists and pages show names and descriptions only. A value appears only
  after pressing "Show value", which is a POST with the CSRF token, so it
  never lands in a URL, browser history or a cache (`no-store`).
- Every view is audit-logged (`secret.reveal`, "web UI") and updates
  "last read", the same as an agent read.
- You can still replace a value, roll back to the previous one (one level
  of history), or delete it.

Each secret has a description ("what this is for and what to do with it"),
an optional usage hint and an optional expiry date. The description is the
main way the human tells the agent what to do.

### Namespaces and agent tokens
Secrets live in namespaces (`homelab/CLOUDFLARE_API_TOKEN`,
`wedding/CONVEX_DEPLOY_KEY`).
Each agent has its own token, granted one or more namespaces, read-only
unless writing is allowed.

- An agent can't see other namespaces at all. A secret in a namespace the
  token isn't granted returns 404, exactly like one that doesn't exist, so
  the names don't leak.
- Grants are per namespace, not per secret, so permissions stay easy to
  follow. A shared namespace granted to two tokens covers keys both need.
- Agents never get admin rights. Only the human (in the UI) creates
  tokens, changes grants or sees every namespace.
- A token is a 0600 file per Unix user, so two users on one machine can
  have different scopes.
- When a token has exactly one namespace, the CLI accepts a bare `NAME`
  instead of `namespace/NAME`.
- **Secret names are env-var style** (`CLOUDFLARE_API_TOKEN`: capitals,
  digits, `_`). A secret is almost always used as an environment variable,
  so its name is the variable name and `run -e NAME` needs no mapping.
  Namespaces and token names stay lower-case, so a ref like
  `homelab/GITHUB_PAT` reads unambiguously. The UI upper-cases what's typed,
  since a phone keyboard defaults to lower case.

### Pairing
Pasting a token means it passes through a clipboard, a chat or a terminal,
which are the places keydrop exists to keep secrets out of. So a machine
**pairs** instead, once:

1. The agent runs `keydrop pair --url …`. The server records a request
   (the source address it saw, plus a host and user name the machine
   claims) and answers with a short code, an approval link and a private
   poll secret. The agent relays the link and code to the human in chat;
   neither is secret, since only a logged-in admin can act on the link.
2. The admin opens the link, checks the code matches what the agent
   showed, and sets the name, namespaces, write access and allowed
   sources (pre-filled with the request's address).
3. The CLI, polling with its poll secret, gets the token once and writes
   it to a 0600 file.

- **Unauthenticated, so bounded.** Anyone who can reach keydrop can ask to
  pair, so requests are capped (3 waiting per address, 8 per IPv6 /64,
  50 overall). When the list is full, the oldest unapproved request from
  the busiest address (or /64) makes way, so one noisy host can't keep
  everyone else from pairing. Requests
  expire after 10 minutes. They're held in memory only: a restart drops
  them, and the agent asks again.
- **The token goes back only to the address that asked**, and only once.
  The poll secret is 256-bit and stored hashed. A poll from another
  address gets 403 and a `pair.wrongaddr` log entry, not "expired", so an
  agent whose address changed knows to ask again from the new one.
- **No orphan tokens.** If an approved token isn't collected within 10
  minutes, it's revoked. The deadline is stored with the token, so this
  holds across a restart, and the revoke matches that token, never just
  the name (a newer token of the same name is safe).
- The claimed host and user are shown as unchecked and cleaned to a safe
  character set; the address is what the admin should trust.
- Re-pairing under an existing name needs "Replace it", which revokes the
  old token, so a machine rebuild doesn't leave two working tokens. The
  form is checked before anything is revoked.
- `keydrop login` (paste a token made by hand) stays for scripts and
  machines that can't wait for an approval.

### Allowed sources
A token can be limited to addresses and CIDR ranges. Use from anywhere
else gets 403 and a `token.denied` log entry, and isn't counted as "last
used". The point is that a token copied off its machine (into a log, a
backup, another box) is useless elsewhere. Empty means anywhere, for
tokens made by hand. The address is the one `KEYDROP_TRUSTED_PROXIES`
resolves, so behind a proxy keydrop has to be told which proxy to trust.

### Agent label
Agents on one machine share its token (they run as the same user, so
separate tokens wouldn't separate anything). `KEYDROP_AGENT=claude` sends
a label that the log shows next to the token's name. It's only a label:
anything holding the token can claim any label, so it's for reading the
log, not for access control.

### Using a secret without seeing it
- `keydrop run -e NAME -- CMD` puts the value only in the child's
  environment, as `$NAME` (`-e VAR=NAME` renames it). Each secret is named
  on the command line, so every read is logged per secret. There's no
  "inject everything" and no `{{NAME}}` substitution in arguments: argument
  values are visible in `/proc/<pid>/cmdline` to the same user.
- **Output masking:** the CLI wraps the child's stdout and stderr and
  replaces each value with `[keydrop:ref]`. That includes base64 and
  URL-encoded forms. Base64 is matched at all three alignments, because a
  Basic-auth header encodes `user:secret` in one piece and the secret's
  own encoding only appears when `len(user)+1` is a multiple of 3; the one
  or two characters at each edge that mix in the neighbouring bytes stay
  visible. It's a streaming masker that holds back bytes only while they
  could still be the start of a secret, so interactive output isn't
  delayed. Every byte of every occurrence is masked: occurrences that
  overlap (one secret a prefix of another, or the end of one the start of
  the next) merge into one placeholder naming each, like
  `[keydrop:A,B]`, and the result is the same however the output is split
  into writes. A span that could still grow is held until it can't, up to
  64 KiB; past that (the same secret repeated back to back without end) it
  is replaced up to there and the rest still masked as it arrives.
  Patterns are indexed by their first two bytes, so the cost per byte
  barely grows with the number of secrets (`go test -bench . ./internal/mask`).
  Values shorter than 4 characters aren't masked, since that would mangle
  normal output.
- **What masking can promise:** accident prevention for honest tools. It
  doesn't catch hex, JSON-escaped, case-changed, truncated or split
  output, or anything the command sends to a file or the network.
- `run` removes every `KEYDROP_*` variable (token, token file, URL, pin)
  from the child's environment, forwards signals, and exits with the
  child's exit code. That keeps the token out of the child's way, not out
  of its reach: the child runs as the same user and can read
  `~/.config/keydrop/token`. `run` isn't a sandbox. `run --no-mask` is
  recorded in the audit log.
- A plain `get` only prints variables. For a secret it refuses and points
  at `run -e`. `get --to-file` (0600) covers config files; with `--force`
  it writes a new 0600 file and renames it into place, so it never keeps a
  looser mode or writes through a symlink. `get --raw` exists for the rare
  pipe, and is easy to block with an agent hook.
- Everything the CLI prints that came from the server (descriptions,
  usage, variable values on a terminal, names, error messages) has control
  characters, terminal escapes and bidirectional overrides shown as
  visible escapes. Descriptions are written by other people and agents,
  and agents read this output.
- `put` takes text up to 60 KiB from stdin, and refuses anything that
  isn't valid UTF-8 rather than letting JSON mangle it: base64 a binary
  value first.
- A pin with an `http://` URL is an error, not silently unchecked, and a
  pinned client won't follow a redirect away from https.

### Variables
Not everything an agent needs is secret: an API base URL, an account ID, a
zone name. Keeping those in a `.env` next to keydrop means two places to
look, and storing them as secrets makes them awkward (masked in output,
every read logged, no way to just look). So an entry is either a
**secret** or a **variable**, chosen when it's added and changeable later.

- Secrets and variables share one keyspace per namespace, so `run -e`
  takes either and one command can mix them.
- A variable's value is shown in the web page and returned in API lists.
  Reading one isn't recorded (no "last read", no audit entry), and `run`
  doesn't mask it.
- Variables are still encrypted at rest and still namespaced: a token sees
  only the variables in its own namespaces.
- The web page and the CLI list them separately (`keydrop secrets`,
  `keydrop vars`), so a list of settings never mixes in key names and the
  other way round.
- Marking a secret as a variable is the admin's call, made in the UI or by
  a write token, and logged.
- **Kind belongs to each value, and defaults to secret.** A write that
  doesn't say "variable" stores a secret, even over an existing variable,
  so a generated password can't land in a list. The previous value keeps
  its own kind, so rolling back after a kind change can't bring back an
  old secret as a variable. The API reads the kind under the same lock as
  the value, so a kind change mid-read can't skip the audit log.

### Telling the agent about new keys
- **Push (the human adds a key):** the secret is marked *new* until an agent
  runs `keydrop ack`. Each token has its own inbox: an ack records the
  token's name on the current value (`acked_by`, cleared when the value
  changes), so one agent's ack doesn't hide a change from another, and a
  read-only token's ack changes nothing anyone else sees except the
  admin's "no agent has picked it up yet" badge. `keydrop inbox` lists new secrets with their
  descriptions, and is designed to run from a session-start hook. There
  are no webhooks or chat notifications: telling a person about anything
  is the job of whatever runs the agents, not of keydrop.
- **Pull (the agent needs a key):** `keydrop request NAME --desc …` creates
  an empty placeholder and returns a link to it. The agent sends the link
  to the human, who opens it on their phone and pastes the value.
  `keydrop wait NAME` returns once it has one. In practice most keys start
  as "I need a token for X", so this is probably the most-used flow.
  Read-only tokens may request. Only the token that made a pending request
  can change its description (another gets 409), because other agents
  read that text: it mustn't be a channel for one agent to instruct
  another.

### Audit log
- Anyone who can reach keydrop can cause some events without a credential
  (`api.badtoken`, `pair.request`, `pair.wrongaddr`, `login.locked`).
  Those go through `noisyEvent`: one per minute per address (IPv6: /64) and
  action, 60 a minute in all, and the next recorded one carries the count
  of those left out. So a flood shows up in the log without filling the
  disk. Events that need a token or a session are all logged.
- Every field is cut at 200 bytes (an agent's `?purpose=` included), and
  the file rotates at 10 MiB to `audit.jsonl.1`.

### Storage and encryption
- Each value is encrypted with AES-256-GCM. The additional authenticated
  data binds the ciphertext to its namespace, name and field, so values
  can't be moved between records by editing the file.
- The master key comes from a file (a Docker secret) or an env var, and is
  never written to the data directory. A key-check blob detects a wrong
  master key at startup instead of failing later.
- `tls.key` is stored sealed (AES-GCM, AAD `blob:tls.key`) in a PEM block
  of type `KEYDROP SEALED PRIVATE KEY`, so a copy of the data can't
  impersonate the pinned server. An older plaintext key is sealed in place
  on start, keeping the key and certificate (and so the pin). The PEM type
  ends in ` PRIVATE KEY` on purpose: an older release fails to parse it and
  refuses to start, instead of making a new certificate.
- `keydrop.json` carries an HMAC-SHA256 over the rest of the state, keyed
  with `HKDF(master key, "keydrop state mac")`, separate from the
  encryption key. Without it, write access to the data was enough to add a
  token hash or replace the admin password. The sealed key check says
  whether a MAC is required (`keydrop-key-check:v2`), so stripping the MAC
  doesn't turn the check off; a v1 file is upgraded on open. A MAC failure
  stops the server. `keydrop downgrade-data` puts the v1 key check back
  (and unseals `tls.key`) for going back to an older release.
- What the MAC can't stop: putting back an older complete copy of the
  data, which verifies fine (including a copy from before the upgrade,
  which then gets re-upgraded). Metadata (names, descriptions, the
  password hash, the audit log) is readable without the key.
- Every change is made to the in-memory state and saved before the
  method returns; if the save fails, memory goes back to the last saved
  state, so the UI never shows a change (a revoke, say) that a restart
  would undo. A value that won't decrypt makes rollback fail instead of
  wiping it, and "create unless it exists" is checked under the same lock
  as the write.
- Not done: master-key rotation, and a lock against two servers on one
  data directory. Both are documented limitations.
- Tokens are 256-bit random values with a `kd_` prefix, so they're easy to
  grep for if they leak. Only the SHA-256 hash is stored.

### Admin login
- Password (PBKDF2-HMAC-SHA256, 600,000 iterations, minimum 12
  characters), plus an optional TOTP code. Setup recommends TOTP and
  explains why (the UI can show every value), but on a LAN-only app the
  owner can reasonably choose password only. It can be turned on later in
  Settings, and turning it off needs the password again. TOTP codes can't
  be replayed.
- The password can be changed in Settings. It needs the current password
  (counted against the login limiter, so a stolen session can't guess
  it), and it logs out every other session, so changing the password
  after a suspected leak actually locks the other person out.
- Failed logins: 5 per client and 20 overall per 15 minutes. The global
  limit is what stops a distributed guesser. Each attempt is reserved
  before the password is checked and refunded on success, so parallel
  requests can't get extra guesses. A successful login sets a device
  cookie (random ID, expiry, HMAC with a key derived from the master key;
  1 year); a browser presenting a valid one is limited per device and is
  exempt from the global limit, so a host on the LAN failing on purpose
  can't lock the owner out.
- First run prints a one-time **setup code** in the container log: 6
  characters from an alphabet without 0/O/1/I, with a link that fills it
  in. Its only job is to stop someone else on the network claiming the
  empty install first, so it's short enough to type on a phone: 30 bits,
  with wrong guesses rate-limited (5 per client, 20 overall per 15
  minutes). If someone uses up the overall limit, restarting keydrop
  clears it and prints a new code. It's new on every restart until setup finishes, and works
  once. The authenticator key is only shown after the code is accepted,
  so a bystander can't copy the second factor.
- The authenticator step shows a QR code (for setting up from a computer;
  `internal/qr` is a small stdlib-only encoder), an `otpauth://` link (on
  a phone, tapping it opens the authenticator app) and the key as text.
  `KEYDROP_RESET_ADMIN=true` reopens setup without touching secrets.
- Sessions: a `__Host-` cookie, `HttpOnly`, `SameSite=Strict`, 1 hour idle
  and 8 hours maximum. Every form has a CSRF token, and cross-site requests
  (`Sec-Fetch-Site`) are refused.
- Headers: strict CSP, `X-Frame-Options: DENY`, `no-referrer`, `no-store`.

### Transport
- HTTPS by default with a self-signed certificate kept in the data
  directory. The CLI pins its SHA-256 fingerprint (`KEYDROP_TLS_PIN`), so
  there's no public CA or DNS dependency, and a proxy in the middle can't
  read tokens or values.
- `KEYDROP_TLS=files` uses your own certificate. `off` is only for running
  behind a TLS-terminating proxy on a private network.
- `KEYDROP_TRUSTED_PROXIES` limits who may set `X-Forwarded-For`, so the
  login limiter, allowed sources and pairing see real client IPs. List
  only the proxy's own address: any host in a trusted range can claim to
  be any address. All `X-Forwarded-For` lines are joined and read from
  the right, skipping trusted proxies, so a proxy that adds its own line
  instead of appending can't be fooled by a line the client sent.
- Turning the authenticator on or off, and changing the password, all
  need the current password, so an unattended logged-in browser isn't
  enough.
- **Not designed for the internet.** Reach it over a LAN or a VPN such as
  Tailscale or WireGuard.

### Getting the CLI onto an agent's machine
The server hands out the CLI it was built with: every image carries all
six builds (linux, darwin, windows × amd64, arm64), gzipped in `/cli`.
`GET /install.sh` picks one with `uname`, checks `SHA256SUMS` and installs
it; `GET /cli/<build>` serves the file. Why the server and not GitHub
releases: an agent needs no GitHub access (the repo may be private), and
the CLI's version always equals the server's.

The trust question is the first download, before the agent has paired.
Straight to keydrop, the command is `curl -k --pinnedpubkey sha256//…`:
curl skips the CA check but refuses any server whose public key doesn't
hash to the pin (`--pinnedpubkey` still applies with `-k`). curl can pin a
key, not a certificate, so the server shows both pins: the key pin for
curl and the certificate pin for `keydrop pair`. Both come from the same
self-signed certificate, which is kept, so they stay stable. Through a
trusted proxy the script uses the public URL and normal certificate
checks. The checksum file comes over the same channel, so it catches a
corrupted download, not a malicious server; the pin is what does that.
The script inserts its own URL into the download commands, so a Host header
that isn't a plain host[:port] is refused rather than quoted. It's only
served when the downloads would be verified: over https straight to
keydrop (pinned), or through a trusted proxy whose `KEYDROP_PUBLIC_URL` is
https. Over plain http it's refused, and curl runs with `--proto =https`
so a redirect can't downgrade it.

The downloads are unauthenticated (they hold nothing secret) and capped at
8 at a time, 2 per address (IPv6: /64); a reader that stalls for 30
seconds is cut off, and none runs past 10 minutes. Authenticated API responses carry `X-Keydrop-Version`; the
CLI warns once if it differs. The header isn't sent to anyone without a
token, so the server doesn't announce its version.

### Deployment hardening (recommended in the example compose file)
Non-root, read-only root filesystem, `cap_drop: ALL`,
`no-new-privileges`, master key as a Docker secret. Pin the image by digest
and update deliberately: a bad image of this app exposes every key.

### Configuration
Everything is configured by env vars, with no lab-specific values in the
code. The full list is in the README.

## Build and release
- CI (`.github/workflows/ci.yml`): gofmt, `go vet`, `go test -race`, and a
  Docker build on every push and pull request. Pushes to `dev` then
  publish `ghcr.io/minituff/keydrop:dev` and `:dev-<sha>` (amd64), for a
  test deployment that pins the digest. The image's version is
  `dev-<sha>`, matching the tag. CI also starts the image, installs the CLI
  with its own pinned `install.sh`, checks `--version`, and checks that a
  wrong pin is refused. The bundle comes from the Dockerfile, so no release
  can ship without it.
- Release (`release.yml`, on a `v*` tag): cross-built CLI binaries with
  `SHA256SUMS` on the GitHub release, and a multi-arch image (amd64, arm64)
  on GHCR with SBOM and provenance attestations. GitHub-hosted runners
  only. Don't use a self-hosted runner on a public repo: a fork's pull
  request could run code on it.
- Go cross-compiles from any OS: `GOOS=linux GOARCH=amd64 go build ./cmd/keydrop`.

## Status

v0.1 (MVP), not yet released:

- **Done:** server, web UI, admin password + optional TOTP, namespaced agent
  tokens, `run` with masking, variables, `secrets`/`vars`/`info`/`inbox`/`ack`,
  `request`/`wait`, `get --to-file`, `put`, `import`, `expiring`,
  change password, pairing, allowed sources, agent labels, audit log,
  TLS with pinning, Dockerfile, CI and release
  workflows, unit tests.
- **Tested so far:** unit tests, plus an end-to-end run of the server and
  CLI on Linux. That run covered namespace isolation, a wrong pin being
  refused, `curl -v` masking (plain and base64), exit codes and the request
  flow.
- **Not yet checked:** the UI in a real browser (phone especially), the
  Docker image build, and the CI and release workflows.

## Roadmap

1. **Before v0.1.0:** check the UI on a phone, confirm the Docker build and
   CI, choose a license.
2. **Agent integrations:** ship the example hook scripts from
   [agents.md](agents.md) (session-start inbox, the `--raw` guard) as
   files rather than docs.
3. **Later:**
   - Passkeys (WebAuthn) for admin login.
   - Trusted proxy-header auth (Authelia, Authentik), deliberately left
     out of v1 because a misconfigured proxy would bypass the login.
   - An MCP server exposing **metadata only** (`secrets`, `vars`, `inbox`, `request`).
     A tool that returns values would put them in the transcript.
   - `--stdin-to CMD` (for example `docker login --password-stdin`).
   - Optional per-secret allowlists inside a namespace.
   - Version history beyond one previous value.
   - An OpenAPI description of the agent API.
