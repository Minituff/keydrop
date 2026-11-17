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
- You can still replace a value, restore one of its older values, or
  delete it.

### Value history
One previous value wasn't enough: two bad saves in a row (a wrong paste,
then another; an agent's `put`, then the admin's fix of the wrong key) and
the last good value was gone. Each key now keeps its last five older
values (`MaxVersions`) beyond the current one.

- **Listed, never shown.** The secret page lists them, newest first, as
  "replaced 3d ago · saved by admin · secret", each with a Restore
  button. There's no way to see an older value as it is: restore it, then
  press Show value, which is the ordinary logged view. So Show value and
  the agents' reveal stay the only two ways a value leaves the server.
- **Restoring is a save.** The restored value becomes current and the one
  it replaces goes to the front of the list, so a restore never loses a
  value (the count doesn't change; only a new save pushes the oldest
  out). Each value keeps its own kind and who saved it, so restoring an
  old secret over a variable brings it back as a secret, and a variable
  restored over a canary unmarks it, as any change to a variable does.
- **Addressed by ID, not by place.** Every older value has a random ID,
  kept as it moves down the list. Restore posts that ID (CSRF token,
  admin middleware), so a page that's out of date can't restore a
  different value; an ID that isn't kept any more is refused, changing
  nothing. The old "Roll back" route still works and restores the newest.
- **Logged.** A restore is `secret.rollback` in the audit log, with which
  one it was ("older value 2 of 5, a secret, replaced …, saved by
  token:ci"), never anything about the value. The change log agents read
  says "rolled back", whichever it was.
- **Admin only.** Agents can't list older values, restore one, or tell how
  many there are: nothing in the API or the CLI changed, and a key's API
  responses are the same byte for byte with or without history, canaries
  included. Deleting a key deletes its history. Making a key a canary, or
  ordinary again, keeps its history, as it always kept the previous value.
- **One place per agent.** When a token saves a value, the history keeps
  only each agent's newest older value; the admin's older values, and
  those whose saver isn't known, all stay. So a run of writes by one
  token takes one place (its last-but-one value can still be restored),
  not all five, and holds at most two of its values on a key, current
  included, which bounds what a token can store on keys it didn't create
  (those don't count towards its cap). The admin's own saves and restores
  never drop anything this way: the admin's five-deep history is the
  point.
- **What it doesn't protect against.** A write token can still replace a
  key, and k tokens with write access to it take k places, so they push
  out all but the admin's newest 5−k older values (two tokens alternating
  leave the newest three; five leave none). It's for mistakes, not for
  agents that are out to destroy a key. The audit log and the change log
  still show every write, and a backup of `data/` is still the only copy
  that an agent can't reach. Older values of the keys a token created
  count towards its storage cap, as the previous value always did, until
  the admin saves over the key.

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
  The one narrowing inside a namespace is a key's limit (next section).
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

### Per-key limits
People made a namespace per agent just to keep one sensitive key (a
registrar key, a root cloud credential) from the other agents. Instead, the
admin can limit a key to some of the tokens that have its namespace.

- **It limits use, not visibility.** A token with the namespace but off the
  list still sees the key in lists, `info`, history and `expiring`, exactly
  as before; it can't reveal it (so `run` and `get` fail), put over it at
  any permission (an add token over a key it created included), or ack it
  (ack marks a value as seen, which a token that can't read it shouldn't).
  Those get 403 naming only the asking token. Names inside a granted
  namespace are visible by design, and hiding them would leak anyway: a
  409 on put or request would say a hidden name exists. Flag, status, note
  and request stay allowed: they carry no value, and flag and status are
  how an agent reports a problem with a key it can see.
- **Agents can tell.** Metadata gains `"usable": false` only for a token off
  the list; for every other key and token the answer is byte-identical to
  before. `keydrop secrets`, `info` and the MCP tools say *limited to other
  agents*. A value the token can never read is never `new` to it, so
  `secrets --new` doesn't list it forever. `APILevel` went to 4 for the
  field; `MinCLILevel` didn't move: an older CLI ignores it and prints the
  403 like any other error.
- **Order of checks.** The namespace check comes first (404, or 403 for a
  put), then the rate limits, then the limit, in the store, under the same
  lock as the value. So a refused reveal counts towards the reveal limit,
  can't be used to hammer, and is logged as `secret.read.denied` (with the
  agent's purpose) in the main log, like the read it replaces. A refused
  put or ack isn't logged, like other refused writes.
- **An empty list means no agent, never everyone.** A revoked token comes
  off every list (forgetToken), so a new token given its name, by hand or by
  pairing again with *Replace*, doesn't inherit the access; a list left
  empty stays a limit. A renewal keeps the token's name and so its place. A
  token that loses a namespace comes off the lists of that namespace's
  keys, so a list only names tokens that have the namespace and the page
  shows who can really use the key; granting it back doesn't restore the
  place. There's no token rename.
- **Secrets only.** A variable's value is in every list, so a limit on one
  would mean nothing. The store refuses to limit a variable and to make a
  limited key a variable by any path (the admin's value or details forms,
  restoring an older variable value, filling a request, an agent's put
  with `variable`); lift the limit first. A pending request can be limited:
  it's just a key.
- **Canaries.** The check doesn't look at the canary flag, so a limited canary
  and a limited ordinary secret give every token the same status, headers
  and body, and `usable` the same way. A refused reveal, put or ack on a
  limited canary is a touch (Inbox, alert, audit), as every other refused
  call on one is. As for those, only the canary's refusal writes the touch
  to disk.
- **Admin only.** The form is on the key's page (CSRF, logged as
  `secret.limit` with the token names). Like a canary it records no history
  entry and leaves `updated_at` alone: agents read the history.
- **Not strippable.** See [Data format history](#data-format-history): the
  first limit seals `keydrop-key-check:v7`, so deleting the limits (with
  `mac7`) doesn't give a loadable file, and v0.1.3 refuses the data until
  `downgrade-data` removes them.
- Not covered by the admin's views: older values, expiry alerts, the Inbox,
  duplicate-value warnings and restore are admin-only and unchanged. A key
  an add token created still counts towards its storage cap after it's
  limited away from it.

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
  the busiest address (or /64) makes way, if it has more waiting than the
  newcomer's address plus one, so one noisy host can't keep everyone else
  from pairing. When no address is busier (say 50 addresses with one
  request each), the oldest unapproved request overall makes way, so a
  full list never shuts pairing off. An approved request is never
  dropped. Requests
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
  from the UI. A canary can be limited like any key, and stays
  indistinguishable (see [Per-key limits](#per-key-limits)). Limitation: `keydrop vars` lists variable values
  without recording a touch, so if an agent's write turns a canary into a
  variable, from then on only calls on that name count.
- The Inbox keeps one entry per (canary, token): first and last touch, a
  count, and the first 5 addresses. The first touch is never overwritten.
  Entries are capped at 100; past that, new ones are only counted (the
  audit log has them all). The admin dismisses entries.
- **Alerts** go to the webhook added in Settings, or else
  `KEYDROP_ALERT_WEBHOOK`. The body names the canary, the token, the address and the
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
  most 30 seconds and twice. Refused token collects use the same path;
  [Inbox alerts](#inbox-alerts) use it too, on a budget of their own.
- **Alert formats** (`KEYDROP_ALERT_FORMAT`, nothing in the state file):
  `discord` is a JSON `{"content": ...}` with `allowed_mentions` empty, so
  a name can't ping anyone; `slack` is `{"text": ...}` with `&`, `<` and
  `>` escaped as Slack asks, so nothing becomes a mention or a link (names
  and addresses can't hold them; the escaping stays in case another
  route opens); `text` is the message as a plain body
  without the backticks, for ntfy. `auto` picks `slack` only for an https
  URL on `hooks.slack.com` and `discord` otherwise, which is what every
  release before it sent. It never guesses ntfy: self-hosted ntfy runs on
  any host and path, and a wrong guess would quietly break a receiver that
  takes the Discord body. The queue holds the message text and the body
  is built when it's posted, from the URL and format then in use, so an
  alert queued before the webhook changes in Settings goes out in the new
  webhook's shape.
- **Revoke on read** (Settings, off by default) revokes a token the moment
  it touches a canary. It stops a stolen token at once, but it also
  tells whoever holds the token that the secret was a trap (their next
  call fails) and lets anyone who can make an agent read a name revoke
  that agent. Off, the canary stays quiet and the admin decides.

### Inbox alerts
An agent that asks (pairing, `request` then `wait`, renewal, a flag) blocks
on a human who has no reason to look at the Inbox. With Inbox alerts on
(in Settings, or `KEYDROP_ALERT_INBOX=true`) the alerter also posts a
notice when a pairing, a key request (single or batch), a renewal request (only when a new one is
created) or a flag is stored. Not notes or description proposals: nothing
waits on them.

- **Opt-in, and the admin's call in Settings.** Settings has On, Off and
  Default; Default (nothing chosen) follows `KEYDROP_ALERT_INBOX`, off
  unless set. A choice made in Settings wins over the variable, on or off,
  as a webhook added there does, so the person looking at the page
  decides what it says. It's stored as `notify.inbox` in the state file,
  under `mac7` (see [Data format history](#data-format-history)), so v0.1.3
  still opens the data and ignores it. It neither grants nor restricts
  access, so it isn't tied to the key check: stripping `notify` and `mac7`
  together only puts it back to Default. Changing it is a CSRF-checked
  admin form, logged as `settings.alertinbox`. Whether a webhook is
  configured is checked at send time, since it too can change in Settings;
  the startup log says what's in effect and where it came from, and when
  it's on without a webhook.
- **Notices can't cost a security alert anything.** They go through the
  one alerter but have their own budget (3 at once, then one per 2
  minutes), spent *instead of* the security budget, never as well, and
  may fill at most half the 32-slot queue, so canary alerts always have
  room. Notices over the budget are counted and sent as one summary of
  their own, on the notice budget. Each kind is sent at most once per key
  per 10 minutes, by kind and token name, so an agent asking for five
  keys sends one notice.
- **Pairing can't cost an agent's notice anything either.**
  `/api/v1/pair` needs no credential, so anyone on the network can cause
  pairing notices, from as many addresses as they have. They have a
  budget of their own again (2 at once, then one per 5 minutes), a
  dedupe map of their own (by the address's source group, the same /64
  grouping as the pairing caps), a summary of their own ("N more machines
  asked to pair"), and at most a quarter of the queue. So a flood of
  pairing requests can't spend the budget, fill the map or take the
  queue room that a token's request, renewal or flag notice needs; it
  only delays other pairing notices. Each map is bounded: past 10,000
  keys a notice is refused rather than grow it, and counted in its
  class's summary, so it isn't lost silently. The agents' map is keyed by
  token names, which only the admin makes.
- **Server-built text only.** A notice names the token, `ns/NAME`, a
  count of keys, or the source address, and links to `/inbox` (or
  `/pair/ID`) only when `KEYDROP_PUBLIC_URL` is configured, not guessed;
  both need the admin's login. Never a value or token, and never agent
  text: descriptions, usage and flag reasons and links are untrusted and
  for the admin's pages, and a pairing's claimed host and user are
  chosen by whoever asked. Not the pairing code either: the admin compares
  the code on the page with the one on the agent's terminal, and the
  webhook channel mustn't be a third place it comes from.
- **Canaries stay indistinguishable.** A flag on a canary sends only the
  canary alert (which already says it was flagged and by whom), not a
  notice too. The agent sees no difference: both are sent in the
  background after the flag is stored, and the response is the same. A
  key request can't touch a canary: a name that has a value, canary or
  not, is refused with the same 409 and sends nothing.
- Refused calls send nothing, and notices add no audit entries: the
  events they announce are already logged.

### Expiry alerts
`keydrop expiring --check` only helps if someone wires it into a health
check; otherwise the first sign an API key expired is an agent's job
failing. "Warn me before a key expires" in Settings (Off, 7, 14 or 30 days)
has the server tell the alert webhook ahead of time.

- **Owned by the server, on the server's clock.** `Server.RunBackground`
  (started by `keydrop server` with the context that stops it on SIGTERM)
  checks a minute after start, then hourly, and soon after the setting or
  the webhook changes. It uses the injectable clock, so tests move time.
- **Announce on entering, not daily.** A key is announced when it newly
  comes within the window, and once more when it newly passes its date.
  The record of what was announced is per key and holds the date it was
  announced for: a new date re-arms it, as does leaving the window (date
  removed or moved out, key deleted) and coming back. Turning the setting
  off forgets it.
- **In memory, not in the state file.** Recording it there would be a new
  MAC'd field and another migration for something that grants nothing,
  and a write every hour. The cost: after a restart keys already in the
  window are announced once more. That's acceptable; a missed warning isn't.
- **One digest per check.** Every key newly due goes in one message,
  soonest first, at most 8 named and the rest counted, so a namespace of
  keys sharing a date can't flood the channel.
- **On the notice path.** The digest spends the notices' budget and half
  the queue, never the security budget, so it can't delay a canary alert.
  If it can't be queued (budget spent, or no webhook), nothing is marked
  and the next check tries again with the same keys; it isn't added to the
  held-notice summary, which would lose the names. Pairing notices have
  their own budget, so a flood of them can't delay it; agents' own
  requests, renewals and flags can, hour by hour, and the Secrets page
  still marks the keys.
- **Names and dates only.** `ns/NAME` and how far off the date is, built by
  the server: never a value, and never a description or usage, which an
  agent may have written. The link (to `/`, which needs the admin's login)
  is there only when `KEYDROP_PUBLIC_URL` is configured, not guessed.
- **Which keys.** Secrets and variables that have a value and a date.
  Pending requests have nothing to expire yet. Canaries are left out: the
  channel is the admin's, so naming one leaks nothing to agents, but a
  decoy's date is there to look real, and nobody renews a decoy. Agents
  can't observe any of this: no API, CLI or `APILevel` change.
- The setting is `notify.expiry_days` in the state file, under `mac7` like
  `notify.inbox`, and like it isn't tied to the key check: stripping
  `notify` and `mac7` together only turns expiry alerts off. Changing it is
  a CSRF-checked admin form, logged as `settings.alertexpiry`.

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
- `keydrop run --stdin NAME -- CMD` (at most once, with or without `-e`)
  gives one value to the child on its stdin instead, for tools that read a
  credential there (`docker login --password-stdin`). It's fetched, logged,
  labelled and masked exactly like an `-e` value, and goes nowhere else (not
  the environment unless it's also named with `-e`, not argv, not a file).
  The child's stdin is a pipe that carries the stored bytes and then EOF:
  no newline is added, because these tools take a trailing newline as part
  of the password (or strip it, which a value ending in one would lose), and
  keydrop's own stdin isn't forwarded after it, so nothing else can be
  appended to the credential. The value is written from a goroutine; a
  child that exits or closes stdin without reading it just ends the write
  (EPIPE, which Go returns rather than raising SIGPIPE on a descriptor other
  than 1 or 2), and the write is cut off once the child exits, so a
  descendant that holds stdin open can't keep keydrop waiting on it. A NUL
  byte, which `-e` refuses because an environment variable can't hold one,
  is fine on stdin.
- **Output masking:** the CLI wraps the child's stdout and stderr and
  replaces each value with `[keydrop:ref]`. That includes base64 and
  URL-encoded forms. Base64 is matched at all three alignments, because a
  Basic-auth header encodes `user:secret` in one piece and the secret's
  own encoding only appears when `len(user)+1` is a multiple of 3; the one
  or two characters at each edge that mix in the neighbouring bytes stay
  visible. Line-wrapped base64 is matched too, at the widths tools use
  (76 for coreutils `base64` and MIME, 64 for PEM and `openssl base64`;
  `\n` or `\r\n`), for values up to 4 KiB: each place the first line break
  can fall is a pattern of its own. When a break falls within the first 4
  characters, those stay visible (matching from the start would hold back
  every line that ends in one of an encoding's first characters). URL
  encoding covers the escaping of Go's `QueryEscape` and `PathEscape`,
  Python's `quote`, JavaScript's `encodeURIComponent`, `encodeURI` and
  `URLSearchParams`, and an encoder that escapes everything but letters
  and digits, each with upper- or lower-case hex. It's a streaming masker that holds back bytes only while they
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
  catches the value as is, its base64 (standard and URL-safe, any
  alignment, unwrapped, or wrapped at 64 or 76 columns for values up to
  4 KiB) and the percent-encodings above. It doesn't catch hex,
  JSON-escaped, case-changed, truncated or split output, base64 wrapped at
  other widths or of a longer value, other encodings, or one encoding
  inside another. And it only sees the command's stdout and stderr:
  anything the command writes to `/dev/tty`, a file, a socket or the
  network isn't masked.
- `run` removes every `KEYDROP_*` variable (token, token file, URL, pin)
  from the child's environment, forwards signals, and exits with the
  child's exit code. The child gets only stdin, stdout and stderr: on Unix
  any other descriptor keydrop itself inherited (a shell's `3>&1`) is
  marked close-on-exec first, since output written there would skip the
  masking. That keeps the token out of the child's way, not out
  of its reach: the child runs as the same user and can read
  `~/.config/keydrop/token`. `run` isn't a sandbox. `run --no-mask` is
  recorded in the audit log.
- A plain `get` only prints variables. For a secret it refuses and points
  at `run -e`. `get --to-file` (0600) covers config files; with `--force`
  it writes a new 0600 file and renames it into place, so it never keeps a
  looser mode or writes through a symlink. `get --raw` exists for the rare
  pipe, and `keydrop guard` blocks it in an agent's session.
- **`keydrop guard`** is a Claude Code `PreToolUse` hook (or, with
  `--command`, a check any agent's wrapper can call). It's a subcommand
  rather than a script because the CLI is already on every agent machine,
  at the server's version, and keeps itself current with `keydrop
  upgrade`; a script would need its own way there, its own version, and
  python or jq to read the hook's JSON. It reads at most 1 MiB, needs no
  token, config or network, and never builds the API client, so it's fast
  and works before pairing. It blocks `get --raw`, `--no-mask`, and `run
  -- env` or `run -- printenv`. It's kept small on purpose (one file, a
  few minutes to read): a tokeniser that minds quotes and backslashes,
  splits on `;`, `&`, `|`, newlines and parentheses, follows `$(…)`,
  backticks and `sh -c` strings, and skips `VAR=x` and a short list of
  wrappers (`sudo`, `env`, `command`, `exec`, `nohup`, `time`). So a
  mention in an argument (`echo "… --raw"`, `git commit -m`) passes while
  an invocation anywhere in the command doesn't. `$(…)`, backticks and
  `sh -c` share one nesting cap of four, which keeps a 1 MiB command
  quick. Everything a real shell would be needed for is left out and
  listed in [agent-setup.md](agent-setup.md#claude-code-hooks): heredocs
  (whose bodies it reads as commands, so it can block a quoted one),
  `eval`, shell keywords, `echo $NAME` and other ways to print a value.
  Masking already covers the output; the guard only catches the obvious
  mistakes before they run. It fails open: bad JSON, too much input or
  another tool passes, since a guard that broke would block every shell
  command in the session, and it's a guard-rail for honest mistakes, not a
  boundary. Its reason is fixed text and never repeats the command, which
  may hold a pasted value.
- Everything the CLI prints that came from the server (descriptions,
  usage, variable values on a terminal, names, error messages) has control
  characters, terminal escapes and bidirectional overrides shown as
  visible escapes. Descriptions are written by other people and agents,
  and agents read this output. An error the server (or a proxy in front of
  it) sends is also kept to one line of at most 300 characters, newlines
  shown as `\x0a`, so an error page can't print lines that look like
  keydrop's own.
- `put` takes text up to 60 KiB from stdin, and refuses anything that
  isn't valid UTF-8 rather than letting JSON mangle it: base64 a binary
  value first.
- A pin with an `http://` URL is an error, not silently unchecked, and the
  client won't follow a redirect from https to plain http, pinned or not:
  the token or a build would go in the clear.
- The config directory (`~/.config/keydrop`, or under `$XDG_CONFIG_HOME`)
  holds the URL and pin, which decide where the token goes and which
  certificate is trusted. On Unix the CLI refuses it, and the `url` and
  `pin` files, when another user owns them or can write to them; the token
  file must not be readable by others either. With no absolute home and
  no `XDG_CONFIG_HOME` the CLI fails instead of using a directory relative
  to where it runs, where a checkout could have planted a URL.

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
  author in `value_by`, and the CLI quotes it and labels it untrusted.
  `get NAME` and `run -e` keep the value itself exact (scripts read it)
  and put the label on stderr instead, naming the agent. Once
  the admin saves the value, the label goes.
- **The label is stored with the value.** Who saved the current value is
  kept in the key's `versions` (`by`), written on every save by a token,
  a key's first value included, and carried by a restore, so restoring an
  agent's older value brings its label back. It used to be worked out
  from the change log, which a token can age out: the log keeps 500
  events per namespace and drops the busiest token's own oldest first, so
  a few hundred writes to a scratch key made the token's variable read
  as the admin's. The log is now only the fallback for a value with no
  saver stored: one saved before this release, or one in a file the
  previous release (v0.1.3) rewrote, since it drops `versions`. For those
  it's the old behaviour, label included until the token has written
  enough to push its event out; the next save stores the saver again.
  With nothing stored and nothing in the log the value counts as the
  admin's: every token save now stores its saver, and the log keeps the
  admin's events ahead of agents', so that's a value the admin saved, or
  one of those older cases.
- **Kind belongs to each value, and defaults to secret.** A write that
  doesn't say "variable" stores a secret, even over an existing variable,
  so a generated password can't land in a list. The same goes for the
  admin's Replace form, which makes you choose on a variable: otherwise an
  agent could stage a variable and ask for a real key to be pasted into
  it. Each older value keeps
  its own kind, so restoring one after a kind change can't bring back an
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
  token collects (see [Canary secrets](#canary-secrets)) and, opt-in, the
  [Inbox alerts](#inbox-alerts) saying something is waiting. Everything else,
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

### MCP server
`keydrop mcp` is a [Model Context Protocol](https://modelcontextprotocol.io)
server on stdin/stdout, built into the CLI. It's another front end to
commands that already exist, using the machine's pairing (URL, pin, token)
and the same API client, so every server-side rule (grants, canaries, rate
limits, the audit log) applies unchanged and the server needs no change.

- **Metadata only.** A tool result goes straight into the model's
  transcript, which is kept by the provider, logged and often shared, so a
  value there is as good as printed. The tools are `keydrop_secrets`,
  `keydrop_vars`, `keydrop_info`, `keydrop_history`, `keydrop_request` and
  `keydrop_whoami`. None of them calls the reveal endpoint, and a test runs
  every tool against a real server and fails if one does or if the
  secret's value reaches the MCP process at all. As a second line, the
  tools drop any value the server sent with an entry that isn't a
  variable. To use a key, the agent runs `keydrop run -e NAME -- CMD` in
  the shell, as before; the server's `instructions` say so.
- **Variables are included**, with their values: they're the documented
  exception, values agents already see with `keydrop vars`, and they come
  from the same list call, so the server's kind check (`store.VariableValue`
  refuses a secret) decides what has a value, not the CLI. No tool reads a
  variable through reveal, so a variable that turns into a secret while
  it's read can't slip through that way.
- **Agent text stays untrusted.** Each tool returns exactly the text the
  CLI command prints, through the same functions: control characters made
  visible, and descriptions, notes and variables another agent wrote
  quoted under "untrusted text from another agent". A tool result is
  model input, so the quoting matters more here, not less.
- **Left out:** anything that returns or handles a value (`get`, `run`,
  `put`, `import`); `wait`, which blocks for up to half an hour; `flag`,
  `status` and `note`, to keep the first version small (they could be
  added, since they carry no value); and `pair`, `login`, `renew` and
  `upgrade`, which change the machine's setup.
- **Protocol:** JSON-RPC 2.0, one message per line, answering
  `initialize` (protocol versions 2025-06-18, 2025-03-26 and 2024-11-05),
  `ping`, `tools/list` and `tools/call`, one request at a time. stdout
  carries only replies: while it runs, anything else the CLI would print
  there goes to stderr, where its warnings (token expiry, a different
  server build) already go. A line over 1 MiB is answered with an error
  and skipped, malformed JSON gets a parse error, and the server exits 0
  when stdin ends. Tool failures (not paired, not found, the server
  unreachable) are tool results marked `isError`, so the session goes on.
  Each call builds its client afresh, so pairing the machine, or a
  renewed token, takes effect without restarting the MCP client.
- What the server records of these calls (a request, a canary touched)
  names the token, with the `KEYDROP_AGENT` label if the MCP server's
  environment sets one, exactly as for the CLI. Nothing marks a call as
  coming through MCP: the calls are the same, and the reveal `purpose`
  the CLI sends for `run` and `get` doesn't arise, since no tool reveals.

### Diagnosing a setup: `keydrop doctor`
When a command fails, an agent sees one error and has to guess the cause,
and guessing is how it ends up asking for a token in the chat. `keydrop
doctor` runs fixed checks in order, one line each with a next step:
where the configuration comes from (the config directory, and which
`KEYDROP_*` variables are set, by name) and its ownership checks; the
server's `/healthz`, unauthenticated, telling DNS, connection refused,
timeouts, plain http on an https URL and "answers, but not like keydrop"
apart; the certificate (pinned and matching, or not trusted); the token
(`whoami`); its name, namespaces, permission and expiry; the version, with
the same notice every command shows, worded by the self-upgrade setting;
and the clock against the server's `Date`. A failed check skips the ones
that depend on it. Exit 1 if any failed.

- **It changes nothing.** It uses `client.Inspect`, a GET without the
  client's side effects: a 401 doesn't collect and save a renewed token,
  and a different build doesn't write the once-a-day `version-notice`
  stamp. It never lists, reads or reveals an entry, so canaries can't
  tell it ran.
- **A 401 is reported as the server makes it.** Unknown, revoked, replaced
  and long-expired tokens get the same 401 on purpose. Doctor then asks
  the renewal status, which still answers in the renewal grace window or
  for a renewed token not yet collected, so those two cases get their own
  advice; anything else is "refused, pair again". A refused address is a
  403 with its own message, so that one is distinguishable.
- **A pin mismatch is only reported.** The handshake stops before any
  request, so nothing (no token) reaches that server. Doctor prints the
  configured pin and the one presented, points at `rotate-tls` and says to
  get the new pin from the admin. It doesn't offer to trust the presented
  certificate: if the admin didn't replace it, that's what an interception
  looks like.

### Audit log
- Anyone who can reach keydrop can cause some events without a working
  credential (`api.badtoken`, `token.expired`, `token.replaced`,
  `pair.request`, `pair.wrongaddr`, `login.locked`). Those go through `noisyEvent`: one per minute per address (IPv6: /64) and
  action, 60 a minute in all, and the next recorded one carries the count
  of those left out. Past 10,000 tracked address-and-action pairs, those
  idle for a minute are forgotten, their left-out counts moving to the
  overall one, so cycling addresses can't grow memory without bound. So
  a flood shows up in the log without filling the disk or memory. Events that need a token or a session are all logged, except
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
- A view of a secret's value (an agent's reveal, the admin's "Show
  value") is written and fsynced before the value is returned; if either
  fails, the value isn't returned (`audit.Record`). Other events are
  written without waiting for the disk (`audit.Add`), so a flood of them
  doesn't cost an fsync each.
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
  can't be moved between records by editing the file. The field is
  `value`, `previous`, or `version:ID` for an older value in `versions`
  (ID random, made when the value enters the history and kept while it
  moves down the list, so the list shifts without resealing). An older
  value can't be swapped with another, moved to another key, or put in
  `previous`. Moving a value between fields decrypts and re-seals it, and
  one that won't decrypt makes the change fail rather than drop it.
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
| `mac6` | `v6View()` | 903db72 (v0.1.3) | `notify` (Inbox alerts on or off, and the expiry alerts' window, chosen in Settings); per-secret `versions` (value history); per-secret `limit` (the agents that may use a key) | `notify` and `versions` yes, with `mac7`: Inbox alerts follow `KEYDROP_ALERT_INBOX` again, expiry alerts are off, history beyond `previous` is gone. `limit` **no**: see below |
| `mac7` | everything | this one | | |

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
- **Per-key limits restrict access the same way:** stripping a `limit`
  would let every agent with the namespace use the key. The first save
  that writes one seals `keydrop-key-check:v7`, which says `mac7` is
  required, and everything v4 says (`mac4` too). It's checked before
  the v4 step on every save, so once v7 a save never writes v4 over it,
  and it stays v7 when the last limit is lifted, as v4 stays when the
  last expiry goes. v0.1.3 knows only the v1, v2 and v4 key checks, so it
  refuses the file. Every MAC covers the key check, so an older key check
  can't be swapped in on its own to make the limits strippable; putting
  back a whole older copy of the data still works, as above.
- `downgrade-data` goes back one format per run. From v7 it lifts every
  key's limit, lists those keys (each is then usable by every agent with
  its namespace) and puts back the v4 key check, whatever the file holds:
  v7 implied it. `DowngradeV4` and the step to v1 refuse to run while v7
  is in place, since their key checks wouldn't protect the limits. From v4 it drops these
  fields (tokens stop expiring, pending renewal requests are dropped, tokens
  with an uncollected rotation are deleted since only the new token would
  work, canaries become ordinary secrets, the canary Inbox entries go; the
  audit log keeps everything) and lists by name what it dropped; run again,
  it goes back to the v1 key check.
- **Value history and `previous`.** `previous` (with `previous_variable`)
  stays the newest older value, written exactly as before, so v0.1.3
  still rolls back one step. `versions` describes it (ID, when it was
  replaced, who saved it) and holds only the values older than it, plus
  who saved the current value. It's written once a key has a value
  replaced, or when a token saves one (the saver is what labels an
  agent's variable, see Variables), so a key with one value the admin
  saved has none, and a file where only the admin has saved values has
  no `mac7`. An older build rewrites the whole file on every save, so it
  can't leave `versions` describing a `previous` it changed: whatever it
  did (a rollback, a save), the file it writes has the current value and
  `previous` as it left them and no `versions`; this one then shows that
  `previous` as the only older value (its date and saver unknown) and
  builds history again from the next save. History grants and restricts
  nothing, so it isn't tied to the key check: stripping `versions` with
  `mac7` (and nothing else under it set) loses the history, and the
  stored savers, so an agent's variable is labelled from the change log
  again, as in that release.
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
  Left set, it reopens setup on every restart, so with an admin already
  there keydrop logs a warning above the setup code, and once setup is
  done a line saying to remove it and restart.
- Sessions and headers are listed in [Security](security.md#security-design).

### Transport
- HTTPS by default with a self-signed certificate kept in the data
  directory. The CLI pins its SHA-256 fingerprint (`KEYDROP_TLS_PIN`), so
  there's no public CA or DNS dependency, and a proxy in the middle can't
  read tokens or values.
- `KEYDROP_TLS=files` uses your own certificate. `off` is only for running
  behind a TLS-terminating proxy on a private network. So the CLI accepts
  an `http://` URL, but `pair` and `login` warn when it points at another
  machine: the token and values would cross the network in the clear.
- `KEYDROP_TRUSTED_PROXIES` limits who may set `X-Forwarded-For`, so the
  login limiter, allowed sources and pairing see real client IPs. List
  only the proxy's own address: any host in a trusted range can claim to
  be any address. All `X-Forwarded-For` lines are joined and read from
  the right, skipping trusted proxies, so a proxy that adds its own line
  instead of appending can't be fooled by a line the client sent. The
  address taken from the header is rewritten in canonical form, with any
  IPv6 zone dropped and `::ffff:1.2.3.4` read as `1.2.3.4`: a zone is free
  text the client may have written, and one address spelled several ways
  mustn't look like several clients to the limits. The direct peer's
  address is used as the kernel reports it.
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
`SHA256SUMS`, run once (`version`, without any `KEYDROP_*` variable, so
not with the token) before it replaces anything, the old binary kept
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
