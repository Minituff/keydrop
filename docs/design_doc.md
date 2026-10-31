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
| `internal/server` | HTTP: web UI (`ui.go`, `web/`), agent API (`api.go`), TLS (`tls.go`). |
| `internal/client` | API client used by the CLI, including certificate pinning. |
| `internal/mask` | Streaming output masking for `keydrop run`. |
| `internal/qr` | QR code encoder (byte mode, level M) for the authenticator setup. |
| `internal/audit` | JSONL audit log plus an in-memory ring for the UI. |

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

### Using a secret without seeing it
- `keydrop run -e NAME -- CMD` puts the value only in the child's
  environment, as `$NAME` (`-e VAR=NAME` renames it). Each secret is named
  on the command line, so every read is logged per secret. There's no
  "inject everything" and no `{{NAME}}` substitution in arguments: argument
  values are visible in `/proc/<pid>/cmdline` to the same user.
- **Output masking:** the CLI wraps the child's stdout and stderr and
  replaces each value with `[keydrop:ref]`. That includes base64 (so
  Basic-auth headers are caught) and URL-encoded forms. It's a streaming
  masker that holds back bytes only while they could still be the start of
  a secret, so interactive output isn't delayed. Values shorter than 4
  characters aren't masked, since that would mangle normal output.
- `run` removes `KEYDROP_TOKEN` from the child's environment, forwards
  signals, and exits with the child's exit code.
- A plain `get` only prints variables. For a secret it refuses and points
  at `run -e`. `get --to-file` (0600) covers config files. `get --raw`
  exists for the rare pipe, and is easy to block with an agent hook.

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
  runs `keydrop ack`. `keydrop inbox` lists new secrets with their
  descriptions, and is designed to run from a session-start hook. There
  are no webhooks or chat notifications: telling a person about anything
  is the job of whatever runs the agents, not of keydrop.
- **Pull (the agent needs a key):** `keydrop request NAME --desc …` creates
  an empty placeholder and returns a link to it. The agent sends the link
  to the human, who opens it on their phone and pastes the value.
  `keydrop wait NAME` returns once it has one. In practice most keys start
  as "I need a token for X", so this is probably the most-used flow.

### Storage and encryption
- Each value is encrypted with AES-256-GCM. The additional authenticated
  data binds the ciphertext to its namespace, name and field, so values
  can't be moved between records by editing the file.
- The master key comes from a file (a Docker secret) or an env var, and is
  never written to the data directory. A backup of the data without the
  key is useless, which is intended. A key-check blob detects a wrong
  master key at startup instead of failing later.
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
  limit is what stops a distributed guesser.
- First run prints a one-time **setup code** in the container log: 6
  characters from an alphabet without 0/O/1/I, with a link that fills it
  in. Its only job is to stop someone else on the network claiming the
  empty install first, so it's short enough to type on a phone: 30 bits,
  with wrong guesses rate-limited (5 per client, 20 overall per 15
  minutes). It's new on every restart until setup finishes, and works
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
  login limiter sees real client IPs.
- **Not designed for the internet.** Reach it over a LAN or a VPN such as
  Tailscale or WireGuard.

### Deployment hardening (recommended in the example compose file)
Non-root, read-only root filesystem, `cap_drop: ALL`,
`no-new-privileges`, master key as a Docker secret. Pin the image by digest
and update deliberately: a bad image of this app exposes every key.

### Configuration
Everything is configured by env vars, with no lab-specific values in the
code. The full list is in the README.

## Build and release
- CI (`.github/workflows/ci.yml`): gofmt, `go vet`, `go test -race`, and a
  Docker build on every push and pull request.
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
  change password, audit log, TLS with pinning, Dockerfile, CI and release
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
