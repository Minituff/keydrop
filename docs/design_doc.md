# keydrop: design

Why keydrop exists, how it's built and why. The [README](index.md) and the
pages beside this one cover using it. This page is for working on it. The
code layout is in
[AGENTS.md](https://github.com/Minituff/keydrop/blob/main/AGENTS.md), and
what's planned is in [Development](development.md#roadmap).

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
values during normal work, not that they can't. The README and
[Security](security.md) say this plainly, and it shouldn't be watered down.

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

## Design decisions

### Values in the UI: shown on purpose, logged
Values aren't write-only, the way GitHub Actions secrets are: an admin can
mint a token for every namespace and read any value through the API, so
hiding values from the admin would protect nothing, and the person who owns
the keys should be able to check one. Instead:

- Lists and pages show names and descriptions only. A value appears only
  after pressing "Show value", which is a POST with the CSRF token, so it
  never lands in a URL, browser history or a cache (`no-store`).
- Every view is audit-logged (`secret.reveal`, "web UI"), isn't shown if
  that record can't be written, and updates
  "last read", the same as an agent read.
- You can still replace a value, roll back to the previous one (one level
  of history), or delete it.

Each secret has a description ("what this is for and what to do with it"),
an optional usage hint and an optional expiry date. The description is the
main way the human tells the agent what to do.

### Namespaces and agent tokens
Secrets live in namespaces (`homelab/CLOUDFLARE_API_TOKEN`,
`blog/DEPLOY_KEY`).
Each agent has its own token, granted one or more namespaces, with one
permission:

- **read** (the default): use and list keys, request, flag, set a status,
  propose notes.
- **add**: also create new keys, and replace the value only of keys this
  same token created (`ext.created_by`). It can't overwrite the admin's
  keys, another token's keys, or fill a placeholder another token
  requested. It's for agents that generate their own credentials, without
  letting them replace one a person relies on.
- **write**: create and replace anything in its namespaces.

The token stores `write` and `add`; a token with neither is read-only. When
the admin saves a value, `created_by` is cleared: the key is the
admin's from then on, and the add token can't replace it (the key's page
says so). A revoke clears what the token left attached to its name, so a
new token with the same name starts clean: its `created_by`, its acks,
`requested_by` on its pending requests (they become the admin's, so no
token can change or fill them under add permission), and its pending
notes and proposals (dropped: never approved, and nobody left to stand
behind them). Its open flags stay for the admin, marked *token since
revoked*, and don't count against or block the new token. The admin
changes a token's permission under **Agents**.

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
   showed, and sets the name, namespaces, permission, allowed sources
   (pre-filled with the request's address), rotation and self-upgrade.
3. The CLI, polling with its poll secret, gets the token once and writes
   it to a 0600 file.

- **Unauthenticated, so bounded.** Anyone who can reach keydrop can ask to
  pair, so requests are capped (3 waiting per address, 8 per IPv6 /64,
  50 overall). When the list is full, the oldest unapproved request from
  the busiest address (or /64) makes way, so one noisy host can't keep
  everyone else from pairing. Requests
  expire after 10 minutes. They're held in memory only: a restart drops
  them, and the agent asks again. Polls are limited too: 300 a minute per
  address (IPv6: /64), then 429.
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

### Token expiry and renewal
- Every token has a lifetime, picked when it's made (pairing approval or
  "Add an agent"): 30, 90 (the default), 180 or 365 days, or never. The UI
  calls it the rotation ("New token every"), because that's what it is to
  the admin: the agent asks for its replacement and one approval in the
  Inbox swaps it in, rather than the admin re-granting anything.
  `ExpiresAt` is nil for never.
- **An expired token gets exactly the 401 an unknown one gets**
  (`invalid token`), so a caller learns nothing from the difference. The
  unauthenticated audit file records `token expired` with the name, for
  the admin. The check is in the one token check (`LookupToken`), so no
  endpoint can forget it.
- Every authenticated answer carries `X-Keydrop-Token-Expires` (RFC 3339
  or `never`). The CLI warns once per run in the last 30 days, the same
  window the Agents page marks as "soon". `whoami` prints
  `expires: 2027-01-30 (in 90 days)` or `expires: never`. Days round up.
- The Agents page shows when each token's replacement is due, a "Rotate
  now" form with the next rotation, each agent's namespaces (editable),
  and a warning on tokens unused for 30 days or more. Expired tokens stay
  listed until the admin revokes them.
- **Renewal is asked for by the agent and granted by the admin.** `keydrop
  renew` (`POST /api/v1/token/renew`) records a request on the token:
  one per token, asking again is a no-op that says so, and status checks
  and requests are rate-limited per (token, address). The Inbox shows it
  with Approve (with the next rotation) and Decline. If the request came from an
  address other than ones the token was recently used from, the Inbox says
  so in red: a stolen token asking to be renewed looks exactly like this.
  Asking doesn't count as use, and the server remembers the last 8
  addresses per token (in memory only, so a restart forgets all but the
  last), so a thief who makes an ordinary call first doesn't hide the real
  agent's address.
- An expired token can call only `GET`/`POST /api/v1/token/renew` and
  `POST /api/v1/token/collect`, and only for 30 days after it expired
  (`RenewalGrace`). After that it's dead and the agent pairs again. Allowed
  sources still apply to those calls.
- **Approval replaces the token** (as does **Rotate now** on the agent's
  page, which needs no request). The token's hash becomes the new token's at once, so
  the old token stops working for anything but collecting; the store
  keeps a `Rotation` with the old hash, the new token sealed under the
  master key (AAD `rotation:<name>:<new hash>`, so it can't be moved to
  another token), the address that asked, and `CollectBy` (7 days). The
  plaintext of the new token is never stored and never shown to the
  admin. Fail-safe: if the save fails nothing changes, and a file with
  the rotation stripped refuses to load (the v4 key check, below).
- **Collecting** (`POST /api/v1/token/collect` with the old token) returns
  the new one, only to the address that asked for the renewal (the
  address the token was last used from, for an admin Renew). Anything
  else is refused with 403, written to the audit log as
  `token.collect.refused` and sent as an alert. Collecting can be
  repeated until the new token is first used, so an answer lost on the
  way doesn't lose the token; its first use deletes the rotation, and the
  old token is then just unknown. Collects have their own rate limit, so
  renew polling can't use it up. A token whose rotation isn't collected
  within 7 days is deleted (audited) and the agent pairs again.
- The CLI collects on its own: any command that gets a 401 first re-reads
  the token file (another process may have collected), then asks the
  renewal status, and collects an approved renewal. It holds a lock on
  `<token file>.lock`, re-reads the file under the lock, and writes the
  new token with a temp file in the same directory (mode 600), fsync,
  rename and a directory fsync; the config file's url and pin are
  untouched. It prints `keydrop: token renewed; new token saved to
  <path>` and never the token. A token given in `KEYDROP_TOKEN` isn't
  collected, since there's nowhere to keep the new one. `keydrop renew
  --wait` waits for the admin.
- **Pairing and renewal are the only two ways a token is handed over.**
  Both hand it over only to the address that asked, and only after the
  admin approved it in the UI.

### Canary secrets
- The admin can mark a secret as a canary: a decoy that no agent should
  ever use, so any use is an alarm. Only the admin's pages show the flag.
  **To an agent a canary is indistinguishable from a real secret:** the
  same list entries, the same responses and errors, the same work per
  call, and no field, header or timing that differs.
- A touch is any agent call on the canary, refused ones included: a
  reveal or `run`, an ack, a write, a status, a flag or a note (a write that turns it into a variable
  still counts, and keeps the flag). Each one writes an audit entry marked
  canary, updates the Inbox and sends an alert. An agent can't clear the
  flag; only the admin clears it, or turns the secret into a variable
  from the UI. Limitation: `keydrop vars` lists variable values
  without recording a touch, so if an agent's write turns a canary into a
  variable, from then on only calls on that name count.
- The Inbox keeps one entry per (canary, token): first and last touch, a
  count, and the first 5 addresses. The first touch is never overwritten.
  Entries are capped at 100; past that, new ones are only counted (the
  audit log has them all). The admin dismisses entries.
- **Alerts** go to the webhook added in Settings, or else
  `KEYDROP_ALERT_WEBHOOK` (Discord-compatible: a JSON
  `{"content": ...}` with `allowed_mentions` empty, so a name can't ping
  anyone). The body names the canary, the token, the address and the
  time, never a value or a token. The URL is a credential: it's never
  logged, shown, put in an error or the audit log. One added in Settings
  is sealed (AES-GCM, its own AAD) in the `alerts` field under MAC5 and
  never shown again. Settings shows only where it posts: the host, and
  for a Discord webhook the name and channel from Discord's answer to a
  GET on it (cleaned, capped, and the ids checked as digits before
  they make a link). The webhook doesn't restrict access, so unlike the
  MAC4 fields it isn't tied to the key check: stripping it with MAC5
  gives a file the previous release could have written, and alerts fall
  back to the variable. **Send test alert** posts at once, against the
  same budget, and shows the webhook's answer. Other alerts are sent asynchronously, from
  one goroutine with a queue of 32 and a 5-second timeout: at most one
  alert per canary and token every 10 minutes, and a global budget of 5
  at once then one a minute. What's over the budget is counted and sent
  as one summary later. A 429 is waited out for its `Retry-After`, at
  most 30 seconds and twice. Refused token collects use the same path.
- **Revoke on read** (Settings, off by default) revokes a token the moment
  it touches a canary. It stops a stolen token at once, but it also
  tells whoever holds the token that the secret was a trap (their next
  call fails) and lets anyone who can make an agent read a name revoke
  that agent. Off, the canary stays quiet and the admin decides.

### Duplicate values
- When the admin saves a secret whose value equals another secret's, the
  page says `NAME has the same value as OTHER_NS/OTHER_NAME. If that was a
  paste mistake, replace it.` with links to both. The save still happens:
  some secrets really are equal. Batches are checked within themselves
  too. Values are compared in constant time against every stored value;
  two variables that match aren't reported (a shared username is normal),
  a secret that matches anything is. The message names keys only, never
  a value.
  Agents never see it.

### Allowed sources
A token can be limited to addresses and CIDR ranges. Use from anywhere
else gets 403 and a `token.denied` log entry (at most one a minute per
address, so a refused token can't rotate the log), and isn't counted as
"last used". The point is that a token copied off its machine (into a log, a
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
- A pin with an `http://` URL is an error, not silently unchecked, and the
  client won't follow a redirect from https to plain http, pinned or not:
  the token or a build would go in the clear.

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
  a write token, and logged. An add token can't store a variable.
- **A variable from an agent is agent text.** Every token in the namespace
  reads it at once, with no approval, so it's at most 2,000 characters on
  one line with no control or invisible characters. The API names its
  author in `value_by`, and the CLI quotes it and labels it untrusted. Once
  the admin saves the value, the label goes.
- **Kind belongs to each value, and defaults to secret.** A write that
  doesn't say "variable" stores a secret, even over an existing variable,
  so a generated password can't land in a list. The same goes for the
  admin's Replace form, which makes you choose on a variable: otherwise an
  agent could stage a variable and ask for a real key to be pasted into
  it. The previous value keeps
  its own kind, so rolling back after a kind change can't bring back an
  old secret as a variable. The API reads the kind under the same lock as
  the value, so a kind change mid-read can't skip the audit log.

### Telling the agent what changed
- **Push (the human adds a key):** `keydrop history [NAME]` lists what
  happened to the keys a token can see, newest first: created, replaced,
  details changed, requested, deleted, rolled back, status, flagged, flag
  resolved, note approved or removed, description approved. It runs from a
  session-start hook. Reading history changes nothing, so nothing an
  agent does hides a change from another agent. History is kept in
  `keydrop.json`, at most 500 events per namespace, filtered per token by
  namespace on the server; a key the token can't see gives the same empty
  answer as one that doesn't exist. Past 500, the namespace drops the
  oldest event of the token with the most events there, so a token
  flooding a namespace evicts its own events first, never another
  namespace's, the admin's or flags; only when nothing else is left do the
  oldest of those go.
- **New:** a value is *new* to a token until that token reads it (`run`,
  `get --to-file`, `get --raw`, or `get NAME` for a variable); replacing
  the value makes it new to everyone again. `keydrop secrets --new` lists
  what the token hasn't read since it changed, and the admin's page shows
  *new — no agent has picked it up yet* until any agent reads it. The
  admin reading it changes nothing.
- **Pull (the agent needs a key):** `keydrop request NAME --desc …` creates
  an empty placeholder and returns a link to it. The agent sends the link
  to the human, who opens it on their phone and pastes the value.
  `keydrop wait NAME` returns once it has one. In practice most keys start
  as "I need a token for X", so this is probably the most-used flow.
  Read-only tokens may request. Only the token that made a pending request
  can change it (another gets 409), and a token has at most 20 open
  requests (429).
- **Batch requests:** `keydrop request A B C [--group LABEL]` asks for up
  to 10 keys in one namespace at once (`POST /api/v1/requests/batch`).
  Each name gets its own request, linked by a batch id, so the Inbox
  shows them as one card with one "Save all" button. It's all or nothing:
  a name that's taken, or the open-request cap, refuses the whole batch.
  A batch of N counts as N against the write rate limit and the cap.
  LABEL is agent text: it's checked like other agent text, stored on the
  requests as a proposal, shown marked as agent-written, and prefills the
  card's group box. Nothing is grouped unless the admin ticks the box.
  Revoking the token clears the label.
- **Filling a card:** each name has its own field and a secret/variable
  choice (secret by default). An empty field leaves that request open.
  Saving is one store change: every value is saved, or none is.
- **Pasting the downloaded file:** services often hand out a file of
  `key=value` lines. The card has a "Paste the downloaded file" box,
  parsed on the server. Lines may be `key=value`, `key: value` or
  `export KEY=value`, with optional matching quotes around the value
  (only a `#` comment may follow the closing quote; an unclosed quote,
  or any other text after it, refuses the paste); blank lines and `#`
  comments are skipped. An unquoted value with a `#` after a space is
  refused too: it could be a comment or part of the value, so the
  admin quotes it or removes the comment. A line splits at its first
  `=` or `:`. Each line maps to a requested name:
  1. a key equal to the name, ignoring case, maps to it;
  2. otherwise the key must equal the last `_` part of exactly one
     requested name, ignoring case (`key=` maps to `EXAMPLE_API_KEY`,
     `secret=` to `EXAMPLE_API_SECRET`).
  It's strict, and the whole submission is refused, with nothing saved,
  if a line doesn't parse, has no value, maps to no name or to two, if
  two lines map to one name, or if both the paste box and a field are
  filled. Errors name line numbers and requested names only, never a
  value or the line's key.
- **Paste-mistake guard:** every single-value field (the Add form, a key's
  page, each field on a card) refuses a value that has a line break
  (unless "keep whitespace" is ticked) or starts with `KEY=` or `key: `,
  with a hint to paste only the part after `key=` or use the paste box.
  `=` must be followed by something other than `=` or the end, so base64
  padding passes. "Save it exactly as pasted" skips the check (and the
  trimming).
- The only outgoing notifications are the alerts for canaries and refused
  token collects (see [Canary secrets](#canary-secrets)). Everything else,
  including telling a person what an agent did, is the job of
  whatever runs the agents, not of keydrop.

### Groups
- A group belongs to a namespace. It has an id (a slug made from its
  name), a display name (at most 64 bytes, checked like agent text), a
  colour from a fixed palette of 8 names (red, orange, yellow, green,
  teal, blue, purple, pink; the store keeps the name, the UI styles it)
  and an optional one-line description. Each key has an optional group
  id.
- Only the admin makes, renames, recolours and deletes groups, and moves
  keys between them. Deleting a group ungroups its keys; it never deletes
  one. Every change goes in the key's history and the audit log.
- **Auto groups** are worked out when a page or list is shown, never
  stored. A key without a group is grouped by the part of its name before
  the first `_`, when at least two such keys in the namespace share it.
  Its colour is a hash of the prefix, so it stays the same. Everything
  else is "Ungrouped". Pending requests aren't auto-grouped. The admin can
  turn auto groups off in Settings (on by default), and can make an auto
  group a real one.
- Order: by namespace, then the admin's groups by name, then auto groups,
  then "Ungrouped". `GET /api/v1/secrets` gives each key's `group`
  (`slug`, `name`, `color`, `auto`), and `keydrop secrets`/`vars` print
  `[namespace: group]`, `[namespace: PREFIX, auto]` and `[namespace:
  ungrouped]` headings (a plain list when nothing is grouped).

### What agents can say about a key
Other agents read what one agent writes, so agent text mustn't be a
channel for one agent to instruct another. Each kind of annotation is
limited to what it needs:

- **Status** (`ok`, `expired`, `revoked`, `leaked`, `replaced-by NAME`, the
  name validated like any secret name). Any token that can see the key
  sets it, without approval: it's one of a fixed set of words, so there's
  nothing to inject, and a leaked key should be marked at once. Everyone
  sees it with who and when (`secrets`, `info`, `history`, the UI).
  `run` and `get` warn on stderr when handing out a key that isn't ok, and
  still run: refusing would break the agent's work over a claim another
  agent made. The admin sets or clears it on the key's page; a status the
  admin set, no token can clear or change (403) until the admin clears
  it. `replaced-by NAME` must name another key in the same namespace (a
  token sees those, so refusing a missing one says nothing about other
  namespaces).
- **Flags** are a message to the admin: a reason (≤500 characters) and an
  optional http(s) link (≤500). The text is shown to the admin only, on the
  **Inbox** until resolved, then in the key's
  history, and is written into the audit log with the flag, so it
  survives the flag being resolved. Agents see "flagged by X on DATE", in
  `info` and `history` without the text. One open flag per token per key
  (409) and 20 open per token; there's no overall cap, so one token can't
  use up flags for the others.
- **Notes** (≤2000 characters) are proposed by an agent and shown to
  other agents only after the admin approves them, as written or edited;
  while pending, other agents see "N notes awaiting approval". Approved
  notes show with their author, the approval date, and whether the admin
  edited them. One pending note per token per key, 20 pending per token,
  50 notes per key.
- **Descriptions** an agent writes (`put --desc/--usage`, `request
  --desc`) go into a *proposal* beside the description, not into it, and
  follow the same approval as notes; the admin can approve (edited or
  not) or reject it. The form carries the proposal's version, so if the
  agent changes it while the admin is reviewing, approve and reject are
  refused and the admin sees the new one. Once approved, the description
  stays marked as written by that agent until the admin changes its text
  (saving it unchanged keeps the mark).
- Flags, statuses and notes share a per-token rate limit, 60 an hour,
  puts and requests another, 200 an hour, and reveals and acks a third,
  1200 an hour (see [Audit log](#audit-log); all in memory, so a restart
  resets them), then 429. All agent text (descriptions, usage, flag
  reasons and links, notes) is refused if it has control characters or
  invisible formatting characters (Unicode Cf, such as bidi overrides and
  zero-width spaces, and line/paragraph separators), and is escaped in
  HTML (the UI marks agent-written text
  with an *agent-written* badge, and links get `rel="noopener noreferrer
  nofollow"`), and the CLI quotes it under "untrusted text from another
  agent" with no terminal escapes.
- Every admin action on them (status, resolve, approve, edit, reject,
  remove) is a CSRF-checked POST and is audit-logged, as are the agent
  calls.

### Audit log
- Anyone who can reach keydrop can cause some events without a working
  credential (`api.badtoken`, `token.expired`, `token.replaced`,
  `pair.request`, `pair.wrongaddr`, `login.locked`). Those go through `noisyEvent`: one per minute per address (IPv6: /64) and
  action, 60 a minute in all, and the next recorded one carries the count
  of those left out. So a flood shows up in the log without filling the
  disk. Events that need a token or a session are all logged, except
  `token.denied` and `token.ratelimited`, which have the same limit so a
  refused token can't rotate the log.
- Reveals and acks, which each write an entry to the main log, are
  limited to 1200 an hour per token, together (in memory, so a restart
  resets it), then 429 with no value. Without that, a token could read in
  a loop until the record of what it read had left the Log page and, in
  time, every rotated file. The limit is the same for secrets, variables
  and canaries; it's checked after the namespace (so an ungranted one
  still gets its 404), and a refused call on a canary is a touch. The
  refusals are logged as `token.ratelimited` through the same throttle as
  `token.denied`.
- Every field is cut at 200 bytes (an agent's `?purpose=` included),
  except a flag's reason and link, kept whole (up to 1100 bytes) in their
  own field and shown on the audit page as agent-written text; and
  each file rotates at 10 MiB.
- The unauthenticated events go to `audit-unauth.jsonl` (one old copy
  kept) and have their own in-memory list; everything that needs a token
  or a session goes to `audit.jsonl` (five old copies). So noise from the
  network can only rotate itself, never `secret.read` events off the disk.
  The UI merges the two lists by time, and only the last 512 KiB of each
  file is read at start.

### Storage and encryption
- Each value is encrypted with AES-256-GCM. The additional authenticated
  data binds the ciphertext to its namespace, name and field, so values
  can't be moved between records by editing the file.
- The master key comes from a file (a Docker secret) or an env var, and is
  never written to the data directory. A key-check blob detects a wrong
  master key at startup instead of failing later.
- `tls.key` is stored sealed (AES-GCM, AAD `blob:tls.key`) in a PEM block
  of type `KEYDROP SEALED PRIVATE KEY`, so a copy of the data can't
  impersonate the pinned server. The server refuses a plaintext `tls.key`
  (from a development build, or `downgrade-data`) instead of sealing it;
  `keydrop upgrade-data` seals it in place, keeping the key and
  certificate (and so the pin). The PEM type ends in ` PRIVATE KEY` on
  purpose: an older release fails to parse it and refuses to start,
  instead of making a new certificate. A new certificate is only made when
  neither `tls.crt` nor `tls.key` exists; with just one of them keydrop
  refuses to start, since a new certificate would silently change the pin
  every agent holds. Sealing doesn't reach copies made before it: backups
  taken before `upgrade-data` hold the plaintext key. `keydrop rotate-tls`
  replaces the key and certificate (keeping the old pair as `.bak` files)
  for when one of those may have leaked; agents re-pin with `keydrop login
  --pin` and their saved token.
- `keydrop.json` carries an HMAC-SHA256 over the rest of the state, keyed
  with `HKDF(master key, "keydrop state mac")`, separate from the
  encryption key. Without it, write access to the data was enough to add a
  token hash or replace the admin password. The sealed key check says
  whether a MAC is required (`keydrop-key-check:v2`). A v1 key check
  (the format before the MAC) can't be forged without the master key, but
  it can be copied from an old backup or a downgraded copy, so **the
  server never accepts or upgrades v1 data**: it refuses to start and
  tells the operator to run `keydrop upgrade-data` once. That command
  vouches for the file as it is (adds the MAC, seals `tls.key`), so it's
  an explicit step, not something an attacker who can write the data
  directory can trigger by restarting the container. Upgrading on start
  would let anyone with write access to the data directory and any v1 copy
  swap in the old key check, drop the MAC, edit tokens or the admin hash,
  and have the edit accepted. A MAC failure stops the server. `keydrop downgrade-data` puts the v1 key check back
  (and unseals `tls.key`) for going back to an older release; this
  release then refuses the data until `upgrade-data` is run again.
- What the MAC can't stop: putting back an older complete copy of the
  data in the current format, which verifies fine (revoked tokens and old
  passwords come back with it). Metadata (names, descriptions, the
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

### Data format history
Older builds can still read what this one writes, as far as they're able.
Each build checks its newest MAC over everything it parses, so each time
optional fields were added, the old top MAC moved to a view of the state with
those fields zeroed (byte for byte what that build writes), and a new MAC,
keyed with `HKDF(master key, "state mac vN")`, took over the whole state.

| MAC | Covers | The build that reads it | Fields added on top of it | Can they be stripped? |
|---|---|---|---|---|
| `mac` | `legacyView()` | 0d6e2d8 | `history`, `fixups`, per-secret `ext` (status, flags, notes, proposals, `created_by`), the token's `add` | Yes, with `mac2`: only drops annotations, or turns an add token read-only |
| `mac2` | `v2View()` | 265e513 | `groups`, `settings`, a key's `group` and `batch` | Yes, with `mac3`: only drops groups, the auto-groups setting and batch links |
| `mac3` | `v3View()` | 5f2f64e | `expires_at`, `lifetime`, `renewal`, `rotation`, per-secret `canary`, the `canary` state | **No**: see below |
| `mac4` | `v4View()` | 631f015 | `alerts` | Yes, with `mac5`: only loses the webhook |
| `mac5` | `v5View()` | 8acec14 | each token's `self_upgrade` | Yes, with `mac6`: turns self-upgrade off, the cautious default |
| `mac6` | everything | this one | | |

- Each newer MAC is written whenever one of its fields is set, and when the
  MAC or any of those fields is present, it must verify. Stripping every
  field of a set and its MAC gives a file that build could have written,
  which is accepted: that's the same as putting back an older copy.
- **Expiry, renewal and canary fields restrict access:** stripping a token's
  expiry or rotation would revive it. So the first save that writes any of
  them seals a new key check, `keydrop-key-check:v4`, which says `mac4` is
  required whatever the file holds, and only `keydrop downgrade-data` takes
  it back. An older build doesn't know that key check and refuses to start
  ("master key does not match") until `downgrade-data` is run.
- `downgrade-data` goes back one format per run: from v4 it drops these
  fields (tokens stop expiring, pending renewal requests are dropped, tokens
  with an uncollected rotation are deleted since only the new token would
  work, canaries become ordinary secrets, the canary Inbox entries go; the
  audit log keeps everything) and lists by name what it dropped; run again,
  it goes back to the v1 key check.
- When an older build rewrites the file it drops the fields it doesn't know;
  keys and their values stay. The e2e suite starts the older builds on data
  this one wrote, lets them rewrite it, and opens the result.
- Every new optional field has to stay outside every older view (the rules
  are in AGENTS.md). A load-time fix-up (`fixups` counts the ones done)
  changes only fields the previous build also has, or `ext`, so the file
  stays one it can read; when that build rewrites the file it drops
  `fixups`, and the fix-ups run again on what it wrote.

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
- Sessions and headers are listed in [Security](security.md#security-design).

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
releases: an agent needs no GitHub access, and the CLI's version always
equals the server's.

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
seconds is cut off, and none runs past 10 minutes. Authenticated API responses carry `X-Keydrop-Version` and the
compatibility levels below. They aren't sent to anyone without a token, so
the server doesn't announce its version.

**CLI compatibility.** Every build changes the version, so a version
mismatch alone said nothing about whether an older CLI still works, and
warning on every one taught agents to ignore it. So there are two numbers
in `internal/server/compat.go`: `APILevel`, raised when the agent API
changes in a way the CLI depends on, and `MinCLILevel`, raised only when
older CLIs would break. The CLI sends its level; the server refuses one
below the minimum with 426 naming `keydrop upgrade`, and otherwise the CLI
mentions a different build at most once a day. `e2e/compat_test.go` runs
the oldest accepted CLI (a commit per level) against the current server,
so breaking it without raising the minimum fails CI.

**Self-upgrade.** `keydrop upgrade` is install.sh in Go: the same
download from the paired server, over the configured pin, checked against
`SHA256SUMS`, run once before it replaces anything, the old binary kept
as `.bak`. It refuses plain http, since what it downloads gets run. The
checksum file comes from the same server, so it catches a broken download,
not a hostile server; the pin is what vouches for the server.

Whether an agent should upgrade itself is the admin's call, per agent:
**Allow self-upgrade** (a token field, off by default, under MAC6 so the
release before it opens the data and drops it). The server sends it as
`X-Keydrop-Self-Upgrade` and words the 426 by it, and the CLI words its
daily notice by it: on, run `keydrop upgrade`; off, leave it to the user.
`keydrop upgrade` asks `POST /api/v1/cli/upgrade` first (exempt from the
minimum-level refusal, logged either way) and stops on a no. It's
advisory, not a control: the agent runs on a machine that can replace its
own files, so the setting decides what the agent is told and what the
supported path does, not what's possible. Turning it on or off makes the
notice show again the same day, so the agent hears about the change.

### Setting up an agent from one prompt
The setup is written for an agent to follow: the person pastes one
sentence and the agent installs the server or pairs with an existing one,
stopping where only the person can act (saving the master key, the admin
login, approving the pairing). The guide is one template embedded in the
binary, `internal/server/web/agent-setup.md.tmpl`, rendered two ways:

- **A server's own copy**, `GET /setup.md` (no auth), and the same text on
  the admin's **Agents → Set up an agent** page. It has that server's
  address and both pins filled in, and skips installing a server. It
  follows `/install.sh`'s transport rules (the address comes from the
  Host header, checked the same way), because the pins in it are what the
  agent will trust: it's only served over https straight to keydrop, or
  through a trusted proxy with an https public URL. With a certificate the
  system already trusts (`KEYDROP_TLS=files`, or a proxy) it has no pins
  and says so. It holds nothing secret: no token and no setup code, so
  it's fine for anyone on the network to read.
- **The generic copy** in `docs/agent-setup.md`, with placeholders
  (`<server-url>`, `<cert-pin>`, `<key-pin>`) and the steps to install a
  server first. A test (`TestAgentSetupDoc`) fails when the checked-in section
  differs from the rendering; `-update` rewrites it. So the docs can't
  drift from what servers hand out.

The page's short version is `Run curl -fsSk --pinnedpubkey 'sha256//…'
https://…/setup.md and follow it`: the key pin protects the guide itself,
and the guide carries the certificate pin for `keydrop pair`. The pins only
prove which server the agent is talking to. They don't make the agent
trustworthy; the admin's approval of the pairing, the token's permission
and namespaces, and the audit log do that.

### Deployment hardening (recommended in the example compose file)
Non-root, read-only root filesystem, `cap_drop: ALL`,
`no-new-privileges`, master key as a Docker secret. Pin the image by digest
and update deliberately: a bad image of this app exposes every key.

### Configuration
Everything is configured by env vars, with no deployment-specific values in
the code. The full list is in [Configuration](install.md#configuration).

## Build and release
CI, publishing and Renovate are in [Development](development.md). What the
design depends on:

- The end-to-end suite runs as a separate job with the full history, since
  it builds older commits. It also builds a test binary with the `e2eclock`
  tag, whose clock (server and CLI) reads an offset from
  `KEYDROP_E2E_CLOCK_FILE`, to test expiry and the renewal windows without
  waiting; release builds don't include it.
- CI starts the image, installs the CLI with its own pinned `install.sh`,
  checks `--version`, and checks that a wrong pin is refused. The bundle
  comes from the Dockerfile, so no release can ship without it.
- GitHub-hosted runners only. Don't use a self-hosted runner on a public
  repo: a fork's pull request could run code on it.
