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

## Quick start

Paste this into your agent (Claude Code, Codex, …):

> Read https://raw.githubusercontent.com/Minituff/keydrop/main/docs/agents.md and help me set up keydrop.

That sentence is the whole setup. The agent installs the server (or uses
the one you have), installs the CLI and pairs its machine, and stops when
it needs you: to save the master key in your password manager, to create
the admin login in your browser, and to approve the pairing. You can read
everything it will be told first: the steps are in full in
[docs/agents.md](docs/agents.md) (the same text, as a [normal GitHub page](https://github.com/Minituff/keydrop/blob/main/docs/agents.md)).

Already running keydrop? **Agents → Set up an agent** gives a shorter
prompt with your server's address and certificate pins filled in.

The rest of this page explains how keydrop works and how to do each step
by hand.

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
  names. Each token has a permission: **read** (the default), **add** (create
  new keys, and replace only the values of keys this same token created,
  until you save a value there yourself), or **write** (create and replace
  anything in its namespaces). Tokens can be limited to the addresses
  they're used from. Revoking a token drops its pending requests' link to
  it, its pending notes and proposed descriptions; its open flags stay,
  marked *token since revoked*.
- **Pairing instead of pasting tokens.** `keydrop pair` on the agent's
  machine prints a link; you open it, check the code, choose what the agent
  may see, and approve. The agent collects its token directly.
- **Agent CLI.** `keydrop run -e NAME` puts a secret into one command's
  environment under its own name and masks it in the command's output.
  Secret names are env-var style (`CLOUDFLARE_API_TOKEN`), so nothing needs
  translating. `secrets`, `info` and `history` show descriptions, never values.
- **Variables for settings that aren't secret.** A URL, an account ID or a
  zone name can be stored as a *variable* next to the secrets. Variables
  are shown in full in the web page and to agents (`keydrop vars`,
  `keydrop get NAME`), aren't masked, and reading one isn't logged. They go
  into `run -e` exactly like secrets, so one command can take both. The
  web page lists secrets and variables separately.
- **Groups.** You can put keys in named, coloured groups (the **Groups**
  page, or a key's page). Keys not in a group are grouped by the part of
  the name before the first `_` when at least two share it (`CLOUDFLARE_TOKEN`
  and `CLOUDFLARE_ZONE` go under `CLOUDFLARE`); turn that off in Settings.
  `keydrop secrets` and `keydrop vars` print keys under `[namespace: group]`
  headings, and the API lists each key's `group`. Agents can't make groups
  or move keys between them.
- **Agents know what changed.** `keydrop history [NAME]` (run by a
  session-start hook) lists what happened to the keys the token can see,
  newest first: created, replaced, requested, status changes, flags, approved
  notes, with who and when. It's read-only and needs no acknowledging.
  `keydrop secrets --new` lists the values this token hasn't read since
  they changed. An agent can also **ask** for a key: `keydrop request`
  creates an empty placeholder and returns a link for you to fill in, and
  `keydrop wait` blocks until you do. Only the token that asked can change
  a pending request. `keydrop request A B C --group NAME` asks for up to
  10 keys at once: you fill them on one card, and can paste the file you
  downloaded (`key=value` lines) for keydrop to split by name. The group
  name is only a suggestion: nothing is grouped unless you tick the box.
- **Agents report problems; you decide what other agents read.**
  - `keydrop status NAME leaked` (or `ok`, `expired`, `revoked`,
    `replaced-by OTHER`) marks a key for everyone who can see it, with who
    set it and when. `keydrop run` and `get` warn on stderr when they hand
    out a key that isn't ok, but still run. You can set or clear it on the
    key's page; a status you set, agents can't change. `replaced-by` must
    name another key in the same namespace.
  - `keydrop flag NAME "reason" [--link URL]` puts the key on your
    **Inbox**. The reason and link are shown to
    you only (and go into the audit log); agents see "flagged by X on
    DATE". Resolving it takes it out of the Inbox; it stays in the key's
    history.
  - `keydrop note NAME "text"` proposes a note and prints the link to
    approve it. Until you approve it (as written or edited) other agents see
    only "1 note awaiting approval"; then `info` shows it with its author
    and the date you approved it. Descriptions an agent writes with `put`
    or `request` wait for your approval the same way, and stay marked as
    the agent's until you change the text.
  - The web page marks text an agent wrote as *agent-written*, and the CLI
    quotes it as untrusted text from another agent, so it reads as a claim
    and not an instruction.
  - Limits: a reason or link up to 500 characters (links http(s) only), a
    note up to 2000, no control or invisible formatting characters (bidi
    overrides, zero-width spaces); one open flag per token per key and 20
    in all; 20 open requests per token; 60 flags, statuses and notes, and
    200 puts and requests, per token an hour. History keeps 500 events per
    namespace, and a token flooding one evicts its own events first.
- **Expiry dates.** `keydrop expiring --check` exits non-zero when keys
  are about to expire, for health checks.
- **An audit log** of every login, change and secret read (which agent,
  which secret, which command, and whether `run --no-mask` was used). It's
  `data/audit.jsonl`, rotated at 10 MiB with five old copies kept
  (`audit.jsonl.1` … `.5`, at most about 60 MiB). Events that need no
  credentials (a bad token, a pairing request, a locked login) go to
  their own file, `data/audit-unauth.jsonl` (rotated at 10 MiB, one old
  copy), so a flood of them can't push the record of who read what off
  the disk. They're logged at most once a minute per address and 60 a
  minute overall, with a count of what was left out. The **Log** page
  shows both, newest first. Text fields are cut at 200 bytes.

### Security design

| | |
|---|---|
| At rest | Each value is encrypted with AES-256-GCM. The AAD binds the ciphertext to the secret's name, so values can't be swapped between records. The TLS private key is sealed the same way, and `keydrop.json` carries an HMAC (key derived from the master key), so edits made without the master key stop keydrop from starting. The master key comes from a file (Docker secret) and is never stored in the data directory. See [what the master key protects](#what-the-master-key-protects). |
| Agent tokens | 256-bit random, stored as SHA-256 hashes, shown once. They start with `kd_` so they're easy to grep for if they leak. Each can be limited to allowed source addresses. |
| Pairing | The admin approves each machine in the UI. The token is handed over once, only to the address that asked, and a token approved but never collected is revoked after 10 minutes, even across a restart. |
| Admin password | PBKDF2-HMAC-SHA256, 600,000 iterations. Optional TOTP; codes can't be replayed. |
| Login limits | 5 failures per client and 20 overall per 15 minutes; each attempt is counted before the password is checked, so parallel guesses don't get extra tries. A browser that has logged in before carries a signed device cookie and is exempt from the overall limit, so failures from elsewhere on the network can't lock the owner out. |
| Sessions | `__Host-` cookie, `HttpOnly`, `SameSite=Strict`, 1 h idle and 8 h maximum. CSRF token on every form, and cross-site requests (`Sec-Fetch-Site`) are refused. |
| Headers | Strict CSP (no scripts at all), `X-Frame-Options: DENY`, `no-referrer`, `no-store`. |
| Transport | TLS by default with a self-signed certificate. The CLI pins its SHA-256 fingerprint, so there's no public CA and no DNS dependency. |
| Container | distroless (no shell), non-root, read-only filesystem and no capabilities in the example compose file. |

## Installing the server by hand

```sh
mkdir keydrop && cd keydrop
mkdir data && sudo chown 65532:65532 data
docker run --rm ghcr.io/minituff/keydrop genkey > master.key
# Compose mounts the file as it is on the host, and the container runs as
# uid 65532, so give it the key (and only it):
sudo chown 65532:65532 master.key && sudo chmod 400 master.key
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

### What the master key protects

Someone with a copy of `data/` but not the master key can't:

- read any secret or variable value, or the authenticator seed;
- read the TLS private key (`tls.key` is sealed), so they can't pose as
  the server that agents have pinned. **Except in copies made before
  sealing:** a backup of `data/` taken before you ran `keydrop
  upgrade-data` (or after `downgrade-data`) holds `tls.key` in plaintext,
  and sealing the live file doesn't change those copies. If such a backup
  may have been exposed, [rotate the certificate](#rotating-the-tls-certificate);
- change `keydrop.json` (add a token hash, replace the admin password,
  grant a namespace) and have keydrop start on it: its HMAC no longer
  matches and keydrop refuses to start with an integrity error. Removing
  the HMAC and pasting in the key check from an older-format copy (a
  backup from before the upgrade, or a downgraded one) doesn't get around
  it either: keydrop refuses older-format data outright and never upgrades
  it on its own, so such a file isn't accepted unless the operator runs
  `keydrop upgrade-data` on it. Only run that on data you know is your
  own and unedited.

They **can** still see metadata: secret and variable names, descriptions,
namespaces, token names, the admin password's PBKDF2 hash, and the audit
log. And someone who can write to `data/` can put back an **older complete
copy** of it in the current format (a backup taken after upgrading
verifies fine, bringing back revoked tokens or an old password), or
delete it. Protect `data/` like any other backup, just not like the key.

Limitations, by design for now:

- **No master-key rotation.** Changing the key means a new install and
  re-entering the values.
- **One server per data directory.** There's no lock file: two instances
  on one volume would overwrite each other's changes. Run one.

### Upgrading and rolling back

Releases before the sealed TLS key and integrity check wrote
`keydrop.json` without an HMAC and `tls.key` in plaintext. This release
**won't start on that data**: it stops with "keydrop.json is in the format
of an older release … run `keydrop upgrade-data` once". It doesn't upgrade
on its own, because the old format has nothing to check: upgrading vouches
for the files exactly as they are, which is the operator's decision. So the
first time, upgrade by hand. With Compose (data in `./data`, the key as the
`keydrop_master_key` secret, as in `compose.example.yml`):

1. Stop keydrop: `docker compose stop keydrop`.
2. Back up `data/` (for example `sudo cp -a data data.bak-$(date +%F)`),
   and keep that copy as safe as the original: its `tls.key` is plaintext.
3. Point the service at the new image (edit `image:`, then
   `docker compose pull keydrop`).
4. Upgrade the data once, with the new image and the same volumes, secret
   and user: `docker compose run --rm keydrop upgrade-data`.
   It prints each step: `keydrop.json` gets an HMAC (and the sealed key
   check records that one is required from now on), and `tls.key` is
   sealed with the master key. The key and certificate stay the same, so
   **the pin agents hold doesn't change**; it prints the pin so you can
   compare. The sealed copy is written beside the old one and read back
   before it replaces it. Running it again changes nothing.
5. Start it: `docker compose up -d keydrop`, and check `docker logs
   keydrop` shows the same `KEYDROP_TLS_PIN=sha256:…` as before.
6. On an agent, `keydrop whoami` should work without changes.

With plain `docker run`, use the same mounts, environment and user as the
server's container, with `upgrade-data` as the command:

```sh
docker run --rm --user 65532:65532 \
  -v /srv/keydrop/data:/data \
  -v /srv/keydrop/master.key:/run/secrets/keydrop_master_key:ro \
  -e KEYDROP_MASTER_KEY_FILE=/run/secrets/keydrop_master_key \
  ghcr.io/minituff/keydrop:NEW upgrade-data
```

**Earlier releases can't start on upgraded data:** they refuse with
"master key does not match this data directory" and never touch it
(they'd fail on the sealed `tls.key` too, rather than make a new
certificate). To go back, stop keydrop and run the *new* image once with
the same volumes and environment:

```sh
docker compose run --rm keydrop downgrade-data
```

That writes `tls.key` back in plaintext and the key check in the old
format; then switch `image:` back and start the older image. The new
release refuses that data again until `upgrade-data` is run again.
Restoring the backup of `data/` from step 2 also works.

Newer fields (statuses, flags, notes, history, groups, batch requests)
don't need `upgrade-data`. An older release that has the integrity check
starts on data this release wrote, and ignores what it doesn't know. When
it next saves, those fields are gone: rolling back loses groups (the keys
stay, ungrouped), and requests stop being linked as one batch.

### Rotating the TLS certificate

Do this if a copy of `tls.key` may have leaked: in particular a backup
made before `upgrade-data`, which holds it in plaintext. With the server
stopped and the same volumes and environment (`KEYDROP_TLS_HOSTS` sets
the new certificate's names, as on first start):

```sh
docker compose stop keydrop
docker compose run --rm keydrop rotate-tls
docker compose up -d keydrop
```

`rotate-tls` makes a new key (sealed) and certificate, keeps the old ones
as `tls.crt.<time>.bak` and `tls.key.<time>.bak`, and prints the new pin.
Every agent then fails with "server certificate doesn't match" until it
has the new pin. On each agent's machine, as the agent's user (its config
is in `~/.config/keydrop`, or `$XDG_CONFIG_HOME/keydrop`):

```sh
keydrop login --url "$(cat ~/.config/keydrop/url)" --pin sha256:NEW < ~/.config/keydrop/token
```

`login` checks the token against the server with the new pin before it
saves anything, and keeps the token as it was. Replace `KEYDROP_TLS_PIN`
too, wherever it's set. The `install.sh` command on the **Agents** page
changes as well (it pins the new key), and so does the prompt under
**Agents → Set up an agent**. To undo before anyone has
re-pinned, stop keydrop and rename the two `.bak` files back. Once every
agent works, delete them.

Lost the admin password or authenticator? Restart with
`KEYDROP_RESET_ADMIN=true`, use the new setup code, then remove the variable.
Secrets and tokens are kept. To change the password while logged in, use
**Settings → Password**; that logs out every other browser.

**Releases with history, flags, statuses, notes and the add permission**
need no upgrade step: they start on the previous release's data as it is.
Going back to that release also works without a command, but when it
saves a change it drops what it doesn't know: history, statuses, flags,
notes and pending proposals are gone, and add tokens become read-only.
On its first start, a release with proposals turns the text of requests
the previous release still has pending back into proposals for you to
approve (that release wrote it straight into the description), and marks
filled requests' descriptions as written by the agent that asked. It
does this again after the previous release has rewritten the file.

## Pairing an agent by hand

0. Install the CLI. The server hands out its own build for Linux and
   macOS (amd64 and arm64), so the CLI is always the server's version and
   the machine needs nothing but `curl`. The exact command is on the
   **Agents** page and in the server log:
   ```sh
   curl -fsSk --pinnedpubkey 'sha256//…' https://192.168.1.50:8443/install.sh | sh
   ```
   `-k` skips the usual certificate check and `--pinnedpubkey` replaces it
   with a check of keydrop's own key, so a different server can't hand you
   a different binary. Behind a proxy with a real certificate it's just
   `curl -fsS https://secrets.example.com/install.sh | sh`. The script
   picks the build with `uname`, checks it against `SHA256SUMS`, and
   installs to `~/.local/bin` (`KEYDROP_INSTALL_DIR` to change). Windows:
   download the `.exe` from the Agents page. Tagged releases also attach
   every build to the GitHub release. `keydrop --version` shows the build;
   the CLI warns once if it doesn't match the server's.
1. On the agent's machine, as the agent's user (or let the agent run it):
   ```sh
   keydrop pair --url https://192.168.1.50:8443 --pin sha256:…
   ```
   It prints a link and a short code, then waits.
2. Open the link (logged in to keydrop). The page shows the code and the
   address the request came from. Check the code matches, then choose the
   agent's name, its namespaces, its permission (read, add or write), and where it's
   allowed from (pre-filled with that address). Approve.
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
`put` takes text up to 60 KiB; base64 a binary value first.

`keydrop inbox` and `keydrop ack` are the old names: for one more release
`inbox` runs `history --since 72h` and `ack` does nothing (reading a value
is what marks it as no longer new), each with a note on stderr.

To migrate an existing `.env` (needs a token with add or write access):
`keydrop import .secrets.env --dry-run`, then without `--dry-run`. Comment
lines above a key become its description, and each key keeps its name
(keys that aren't upper-case are skipped). Values are never printed. Rotate
anything that sat in plaintext for long. `--vars` imports every key as a
variable instead, for a file of plain settings.

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

The rules to give the agent (for its `CLAUDE.md` or `AGENTS.md`), a
session-start history hook and a guard against `--raw` are in
[docs/agents.md](docs/agents.md).
[docs/design_doc.md](docs/design_doc.md) explains how keydrop is built and
why.

## Configuration

| Variable | Default | |
|---|---|---|
| `KEYDROP_MASTER_KEY_FILE` | — | File holding the master key (preferred). Or `KEYDROP_MASTER_KEY` with the value itself. |
| `KEYDROP_DATA_DIR` | `/data` | State, audit log and the generated certificate. |
| `KEYDROP_LISTEN` | `:8443` | Listen address. |
| `KEYDROP_PUBLIC_URL` | — | Base URL used in links (`request`, `pair`, the setup log line). Unset, `pair` links use the URL the agent connected to. |
| `KEYDROP_TLS` | `auto` | `auto` (self-signed, kept in the data dir), `files` (`KEYDROP_TLS_CERT` + `KEYDROP_TLS_KEY`), or `off` (only behind a TLS-terminating proxy). |
| `KEYDROP_TLS_HOSTS` | — | Extra DNS names/IPs for the self-signed certificate. |
| `KEYDROP_COOKIE_SECURE` | `true` | Set `false` only if the page is reached over plain HTTP. |
| `KEYDROP_TRUSTED_PROXIES` | — | IPs/CIDRs allowed to set `X-Forwarded-For`, so login limits, allowed sources and pairing see the real client. List only the proxy itself: anything in these ranges can claim any address. |
| `KEYDROP_RESET_ADMIN` | `false` | Reopen setup to replace the admin password and authenticator. |
| `KEYDROP_CLI_DIR` | `/cli` in the image | Where the CLI builds the server hands out live (`keydrop-<os>-<arch>.gz` plus `SHA256SUMS`). Unset outside the image: no downloads. |

CLI: `KEYDROP_URL`, `KEYDROP_TOKEN` / `KEYDROP_TOKEN_FILE`, `KEYDROP_TLS_PIN`
override the files written by `keydrop pair` / `keydrop login`. A pin
needs an `https://` URL; with `http://` the CLI refuses rather than skip
the check.
`KEYDROP_AGENT` sets the agent label shown in the log.

### Behind a reverse proxy

keydrop serves HTTPS itself. With Traefik in front, either point Traefik
at `https://keydrop:8443` with a `serversTransport` that skips verification,
or set `KEYDROP_TLS=off` and keep the hop on a private Docker network. Set
`KEYDROP_TRUSTED_PROXIES` to the proxy's IP. The proxy must send
`X-Forwarded-Proto: https` (Traefik does by default); without it keydrop
won't serve `/install.sh` or `/setup.md` through the proxy, since it can't
tell the client didn't use plain http. Agents can still talk to the
container directly with the pinned certificate, so they don't depend on the
proxy or DNS.

**Don't expose keydrop to the internet.** Reach it over your LAN or a VPN
such as Tailscale or WireGuard.

## API

All endpoints except pairing take `Authorization: Bearer kd_…`, and an
optional `X-Keydrop-Agent: label`. A namespace the token isn't granted
returns 404, exactly like a missing secret. A token used from outside its
allowed sources gets 403. Flags, statuses and notes past their hourly limit
get 429, as do puts and requests past theirs, and a request past a token's
20 open ones.

| | |
|---|---|
| `GET /api/v1/whoami` | Token name, namespaces, `permission` (`read`, `add` or `write`) and the older `write` flag |
| `GET /api/v1/secrets?new=1&pending=1&namespace=x` | Metadata list (`kind` is `secret` or `variable`; variables include their `value`; `group` is `{"slug","name","color","auto"}` when the key is in one) |
| `GET /api/v1/secrets/{ns}/{name}` | Metadata, including `status`, open `flags` (who and when), approved `notes`, `pending_notes` and `description_pending` |
| `POST /api/v1/secrets/{ns}/{name}/reveal?purpose=…` | `{"value": …}`, the only endpoint that returns a value (logged); adds `"status"` when the key isn't ok. Marks the value as no longer new to this token |
| `GET /api/v1/history?namespace=x&name=Y&limit=50` | Changes to the keys this token can see, newest first (at most 1000; 500 kept per namespace). Flag reasons aren't included |
| `POST /api/v1/secrets/{ns}/{name}/status` | `{"status","replaced_by"}`; `ok` clears it. 403 if the admin set the current status; `replaced_by` must exist in the namespace |
| `POST /api/v1/secrets/{ns}/{name}/flag` | `{"reason","link"}`. 409 if this token already has an open flag on the key. Flags in `GET` carry `token_revoked` when their token has since been revoked |
| `POST /api/v1/secrets/{ns}/{name}/notes` | `{"text"}` → 201 `{"url"}`, the page where the admin approves it |
| `POST /api/v1/secrets/{ns}/{name}/ack` | Deprecated (older CLIs): clears the *new* flag for this token; reveal does this now |
| `PUT /api/v1/secrets/{ns}/{name}` | `{"value","description","usage","expires","variable","overwrite"}` (add and write tokens; an add token can only replace keys it created; without `"variable": true` the value is stored as a secret, even over a variable). A description or usage from an agent waits for the admin's approval |
| `POST /api/v1/requests` | `{"namespace","name","description","usage"}` → `{"ref","url"}`. 409 if it already has a value, or another token already asked for it |
| `POST /api/v1/requests/batch` | `{"namespace","names","group","description","usage"}` → `{"refs","batch","url","urls"}`: up to 10 keys, filled on one card (`url` points at it). All or nothing; a batch of N counts as N requests towards the limits. `group` is a suggestion shown to the admin as agent-written |
| `GET /api/v1/expiring?days=14` | Secrets expiring within N days (at most 36500) |
| `POST /api/v1/pair` | No auth. `{"host","user"}` (shown to the admin, unchecked) → `{"code","path","link","poll","expires_in"}`. At most 3 waiting per address and 8 per IPv6 /64, 50 overall; when the list is full the busiest address's oldest request makes way for a newcomer |
| `POST /api/v1/pair/poll` | No auth. `{"poll"}` → `{"state":"pending"}`, or once approved `{"state":"approved","token","name","namespaces"}`, exactly once and only to the address that asked (403 from any other). 404 once expired, denied, collected, or the approved token was revoked |
| `GET /healthz` | No auth |
| `GET /setup.md` | No auth. The agent setup guide for this server, with the address it was fetched from and the certificate and key pins filled in (no token, no setup code). Same transport rules as `/install.sh` |
| `GET /install.sh` | No auth. Installer for Linux/macOS; downloads from the address it was fetched from (pinned to keydrop's key when that's keydrop itself). Only over https, or through a trusted proxy with an https `KEYDROP_PUBLIC_URL` |
| `GET /cli/keydrop-<os>-<arch>[.exe]`, `GET /cli/SHA256SUMS` | No auth. The CLI builds, same version as the server; 8 downloads at a time, 2 per address |

Authenticated responses carry `X-Keydrop-Version`, the server's build.

## Building

```sh
go test ./...
go test -tags e2e ./e2e/...                   # end-to-end: the real binary as server and CLI
go build ./cmd/keydrop                        # this platform
GOOS=linux GOARCH=amd64 go build ./cmd/keydrop  # cross-compile (from Windows too)
docker build -t keydrop .
```

Tags `v*` publish CLI binaries with `SHA256SUMS` to the GitHub release, and a
multi-arch image (with SBOM and provenance) to GHCR, from GitHub-hosted
runners. Pushes to `dev` publish an amd64 image tagged `dev` and
`dev-<sha>` (its version is `dev-<sha>` too) once the tests pass; pin it by
digest, not by the moving tag. Every image includes the CLI for all six
platforms (about 24 MB compressed); CI installs it from a running image
with `install.sh` and checks the version before anything is published.
Nothing is published unless the tests passed on that commit. Workflow
actions are pinned to commit SHAs and base images to digests.

## Roadmap

- Passkeys (WebAuthn) for admin login
- An MCP server exposing **metadata only** (`secrets`, `vars`, `history`, `request`). A
  tool that returns values would put them straight into the transcript.
- Optional per-secret allowlists inside a namespace
- Version history beyond one previous value

## License

[MIT](LICENSE)
