# keydrop

A secret drop for homelab AI agents.

You make an API key on your phone and paste it into keydrop's web page. Your
agent (Claude Code, Codex, a script) then **uses** the key without ever
**seeing** it. The value never passes through the chat, the shell history,
the agent's logs, or git.

```sh
# The agent writes this. Only the name appears in its transcript.
keydrop run -e CLOUDFLARE_API_TOKEN -- sh -c \
  'curl -s -H "Authorization: Bearer $CLOUDFLARE_API_TOKEN" https://api.cloudflare.com/client/v4/user/tokens/verify'
```

If the command prints the key anyway (`curl -v`, an error message, a base64
Basic-auth header), keydrop replaces it in the output with
`[keydrop:CLOUDFLARE_API_TOKEN]`.

One small container plus one CLI binary. Written in Go with **no third-party
dependencies**, so the whole thing can be audited in an afternoon.

## What it's for, and what it isn't

**It protects against accidents:** a key pasted into chat (and stored in the
provider's transcript), echoed into a tool's output, saved in shell history,
committed in a `.env` file, or left in plaintext on disk.

**It doesn't protect against a malicious or compromised agent.** Anything that
can *use* a secret can exfiltrate it. keydrop makes sure an agent doing normal
work never sees values. It doesn't make that impossible, and nothing that
hands secrets to a program can.

It's built for one person and a few agents on a home network. It isn't a
replacement for Vault or Infisical in a team.

## How it works

- **A web page for you.** Paste a value with a description of what it's
  for. You can view a value later (press "Show value"; every view is
  logged), replace it, roll back to the previous value, or delete it. Lists
  show names and descriptions only. The page is built for phones, with no
  autocorrect or capitalisation in the value field, and it uses no
  JavaScript.
- **Admin login with a password, plus an authenticator code (TOTP) if you
  turn it on** (recommended, offered at setup with a QR code). Failed logins
  are rate-limited.
- **Namespaces and agent tokens.** Secrets live in namespaces (`homelab/…`,
  `wedding/…`). Each agent gets its own token, granted one or more
  namespaces. An agent can't see other namespaces at all, not even the secret
  names. Tokens are read-only unless you allow writing.
- **Agent CLI.** `keydrop run -e NAME` puts a secret into one command's
  environment under its own name and masks it in the command's output.
  Secret names are env-var style (`CLOUDFLARE_API_TOKEN`), so nothing needs
  translating. `secrets`, `info` and `inbox` show descriptions, never values.
- **Variables for settings that aren't secret.** A URL, an account ID or a
  zone name can be stored as a *variable* next to the secrets. Variables
  are shown in full in the web page and to agents (`keydrop vars`,
  `keydrop get NAME`), aren't masked, and reading one isn't logged. They go
  into `run -e` exactly like secrets, so one command can take both. The
  web page lists secrets and variables separately.
- **Agents know what to do with a new key.** Secrets you add are marked
  *new* until an agent acknowledges them, and `keydrop inbox` (run by a
  session-start hook) shows them with your description. An agent can also
  **ask** for a key: `keydrop request` creates an empty placeholder and returns a
  link for you to fill in, and `keydrop wait` blocks until you do.
- **Expiry dates.** `keydrop expiring --check` exits non-zero when keys
  are about to expire, for health checks.
- **An audit log** of every login, change and secret read (which agent,
  which secret, which command).

### Security design

| | |
|---|---|
| At rest | Each value is encrypted with AES-256-GCM. The AAD binds the ciphertext to the secret's name, so values can't be swapped between records. The master key comes from a file (Docker secret) and is never stored in the data directory. |
| Agent tokens | 256-bit random, stored as SHA-256 hashes, shown once. They start with `kd_` so they're easy to grep for if they leak. |
| Admin password | PBKDF2-HMAC-SHA256, 600,000 iterations. Optional TOTP; codes can't be replayed. |
| Login limits | 5 failures per client and 20 overall per 15 minutes. |
| Sessions | `__Host-` cookie, `HttpOnly`, `SameSite=Strict`, 1 h idle and 8 h maximum. CSRF token on every form, and cross-site requests (`Sec-Fetch-Site`) are refused. |
| Headers | Strict CSP (no scripts at all), `X-Frame-Options: DENY`, `no-referrer`, `no-store`. |
| Transport | TLS by default with a self-signed certificate. The CLI pins its SHA-256 fingerprint, so there's no public CA and no DNS dependency. |
| Container | distroless (no shell), non-root, read-only filesystem and no capabilities in the example compose file. |

## Quick start (server)

```sh
mkdir keydrop && cd keydrop
mkdir data && sudo chown 65532:65532 data
docker run --rm ghcr.io/minituff/keydrop genkey > master.key && chmod 600 master.key
curl -O https://raw.githubusercontent.com/minituff/keydrop/main/compose.example.yml
# edit KEYDROP_PUBLIC_URL and KEYDROP_TLS_HOSTS, then:
docker compose -f compose.example.yml up -d
docker logs keydrop
```

The log prints two things:

1. **A one-time setup code** (6 characters, like `K7Q-MP3`), and a link
   with the code filled in. Go to `/setup`, enter the code, and choose a
   password. The code only proves you can read the log, so nobody else on
   the network can claim the empty install first. Then add keydrop to an
   authenticator app (scan the QR code, or on a phone tap "Add to
   authenticator app"), or choose password only and add one later in
   Settings.
2. **The certificate pin** (`KEYDROP_TLS_PIN=sha256:…`). Agents need this.

**Back up `master.key` separately from `data/`.** Without it the data can't be
read, which is deliberate.

Lost the admin password or authenticator? Restart with
`KEYDROP_RESET_ADMIN=true`, use the new setup code, then remove the variable.
Secrets and tokens are kept. To change the password while logged in, use
**Settings → Password**; that logs out every other browser.

## Quick start (agent)

1. In the web page, under **Agents**, create a token, for example `homelab-claude`
   with namespace `homelab`.
2. On the agent's machine, as the agent's user:
   ```sh
   keydrop login --url https://192.168.1.50:8443 --pin sha256:…
   # paste the token (input is hidden)
   ```
   This writes `~/.config/keydrop/{url,token,pin}` with mode 600.
3. Use it:
   ```sh
   keydrop inbox                                   # anything new for me?
   keydrop secrets                                 # what keys exist (no values)
   keydrop vars                                    # non-secret settings, with values
   keydrop run -e CLOUDFLARE_API_TOKEN -- terraform apply   # sets $CLOUDFLARE_API_TOKEN
   keydrop run -e TOKEN=CLOUDFLARE_API_TOKEN -- sh -c 'curl -H "Authorization: Bearer $TOKEN" …'
   keydrop ack CLOUDFLARE_API_TOKEN                # dealt with it
   keydrop request GITHUB_PAT --desc "Fine-grained PAT for org/repo, contents:read, 90 days"
   keydrop wait GITHUB_PAT
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
600. `keydrop get NAME --raw` prints a secret, which defeats the point; it
exists for the rare pipe that needs it.

To store a variable from the CLI: `echo https://… | keydrop put API_URL --var`.

To migrate an existing `.env` (needs a token with write access):
`keydrop import .secrets.env --dry-run`, then without `--dry-run`. Comment
lines above a key become its description, and each key keeps its name
(keys that aren't upper-case are skipped). Values are never printed. Rotate
anything that sat in plaintext for long. `--vars` imports every key as a
variable instead, for a file of plain settings.

See [docs/agents.md](docs/agents.md) for wiring this into Claude Code and
Codex, with a session-start inbox hook and a guard against `--raw`.
[docs/design_doc.md](docs/design_doc.md) explains how keydrop is built and
why.

## Configuration

| Variable | Default | |
|---|---|---|
| `KEYDROP_MASTER_KEY_FILE` | — | File holding the master key (preferred). Or `KEYDROP_MASTER_KEY` with the value itself. |
| `KEYDROP_DATA_DIR` | `/data` | State, audit log and the generated certificate. |
| `KEYDROP_LISTEN` | `:8443` | Listen address. |
| `KEYDROP_PUBLIC_URL` | — | Base URL used in links (`request`, the setup log line). |
| `KEYDROP_TLS` | `auto` | `auto` (self-signed, kept in the data dir), `files` (`KEYDROP_TLS_CERT` + `KEYDROP_TLS_KEY`), or `off` (only behind a TLS-terminating proxy). |
| `KEYDROP_TLS_HOSTS` | — | Extra DNS names/IPs for the self-signed certificate. |
| `KEYDROP_COOKIE_SECURE` | `true` | Set `false` only if the page is reached over plain HTTP. |
| `KEYDROP_TRUSTED_PROXIES` | — | IPs/CIDRs allowed to set `X-Forwarded-For`, so login limits apply per real client. |
| `KEYDROP_RESET_ADMIN` | `false` | Reopen setup to replace the admin password and authenticator. |

CLI: `KEYDROP_URL`, `KEYDROP_TOKEN` / `KEYDROP_TOKEN_FILE`, `KEYDROP_TLS_PIN`
override the files written by `keydrop login`.

### Behind a reverse proxy

keydrop serves HTTPS itself. With Traefik in front, either point Traefik
at `https://keydrop:8443` with a `serversTransport` that skips verification,
or set `KEYDROP_TLS=off` and keep the hop on a private Docker network. Set
`KEYDROP_TRUSTED_PROXIES` to the proxy's IP. Agents can still talk to the
container directly with the pinned certificate, so they don't depend on the
proxy or DNS.

**Don't expose keydrop to the internet.** Reach it over your LAN or a VPN
such as Tailscale or WireGuard.

## API

All endpoints take `Authorization: Bearer kd_…`. A namespace the token
isn't granted returns 404, exactly like a missing secret.

| | |
|---|---|
| `GET /api/v1/whoami` | Token name, namespaces, write flag |
| `GET /api/v1/secrets?new=1&pending=1&namespace=x` | Metadata list (`kind` is `secret` or `variable`; variables include their `value`) |
| `GET /api/v1/secrets/{ns}/{name}` | Metadata |
| `POST /api/v1/secrets/{ns}/{name}/reveal?purpose=…` | `{"value": …}`, the only endpoint that returns a value (logged) |
| `POST /api/v1/secrets/{ns}/{name}/ack` | Clear the *new* flag |
| `PUT /api/v1/secrets/{ns}/{name}` | `{"value","description","usage","expires","overwrite"}` (write tokens) |
| `POST /api/v1/requests` | `{"namespace","name","description","usage"}` → `{"ref","url"}` |
| `GET /api/v1/expiring?days=14` | Secrets expiring within N days |
| `GET /healthz` | No auth |

## Building

```sh
go test ./...
go build ./cmd/keydrop                        # this platform
GOOS=linux GOARCH=amd64 go build ./cmd/keydrop  # cross-compile (from Windows too)
docker build -t keydrop .
```

Tags `v*` publish CLI binaries with `SHA256SUMS` to the GitHub release, and a
multi-arch image (with SBOM and provenance) to GHCR, from GitHub-hosted
runners.

## Roadmap

- Passkeys (WebAuthn) for admin login
- An MCP server exposing **metadata only** (`secrets`, `vars`, `inbox`, `request`). A
  tool that returns values would put them straight into the transcript.
- Optional per-secret allowlists inside a namespace
- Version history beyond one previous value

## License

[MIT](LICENSE)
