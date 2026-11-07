# Features

Everything keydrop does, in one list. For the short version, see the [overview](index.md).

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
  `media/…`). Each agent gets its own token, granted one or more
  namespaces. An agent can't see other namespaces at all, not even the secret
  names. Each token has a permission: **read** (the default), **add** (create
  new keys, and replace only the values of keys this same token created,
  until you save a value there yourself), or **write** (create and replace
  anything in its namespaces). Tokens can be limited to the addresses
  they're used from. In the UI a namespace is picked from a list; a new
  one is only made by choosing **+ New namespace…** and typing its name,
  so a typo can't quietly create one, and the page then reminds you that no
  agent can read it yet. An agent's namespaces can be changed later on the
  **Agents** page. Revoking a token drops its pending requests' link to
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
- **Tokens are rotated.** Each token is replaced on a schedule you pick
  when you approve or make it ("New token every"): 30, 90 (the default),
  180 or 365 days, or never. Near the end the agent asks for its new token
  by itself; you approve it with one tap in the **Inbox** and the agent
  swaps it in, so nothing else changes. The **Agents** page shows "new
  token due in N days", "token ran out …, waiting for its renewal" or
  "same token, never rotated", points out tokens unused for 30 days or
  more, and keeps run-out tokens listed until you revoke them. A token
  past its date gets the same 401 as an unknown one (the log says "token
  expired"). From 30 days before then every command warns on stderr;
  `keydrop whoami` shows `expires: 2027-01-30 (in 90 days)` or `expires:
  never`.
- **Renewal is a new token.** `keydrop renew` asks you to renew the token
  (also up to 30 days after it expired); the request shows in the
  **Inbox**, where you approve it (picking the next rotation) or decline
  it. Approving, or pressing **Rotate now** on the agent's page under Agents, replaces the token at once:
  the old one can then only *collect* the new one, once (repeatable until
  the new one is first used, in case an answer was lost), only from the
  address that asked, within 7 days. `keydrop renew --wait` waits and
  collects; otherwise the agent's next command does, saves the new token
  over the token file (atomically, mode 600) and carries on, printing
  `keydrop: token renewed; new token saved to <path>`. A renewal not
  collected in 7 days revokes the token: pair the agent again. Nothing
  renews without you.
- **Canaries.** Pick **Canary** as the kind when you add one (or use
  **Make it a canary** on a secret's page) to make a decoy no agent should
  need. Leave the value empty and keydrop fills in a random one shaped
  like an API key. To agents it's an ordinary secret, and they see its
  description and usage, so write those as if it were real. When an agent reads it (or writes, flags, notes or sets a status
  on it), the log marks it *canary*, the **Inbox** shows one entry per
  canary and token (first and last time, count, addresses) until you
  dismiss it, and, with an alert webhook set, keydrop posts an
  alert (at most one per canary and token every 10 minutes; at most 5 at
  once and one a minute after that, the rest summed up in one message).
  Add the webhook in **Settings** (paste a Discord webhook URL; it's
  stored encrypted and never shown again), or set `KEYDROP_ALERT_WEBHOOK`.
  One added in Settings wins; removing it falls back to the variable.
  Settings shows where alerts go (for Discord: the webhook's name and a
  link to its channel), and **Send test alert** sends one at once and
  says whether the webhook accepted it. Settings can also **revoke a
  token that reads a canary**. That's off by default,
  because the revocation tells whoever holds the token which secret was
  the canary. Variables can't be canaries.
- **Duplicate values.** When you save a value in the web page (Add,
  replace, filling a request, a batch card or a pasted file), keydrop
  compares it in constant time with every other stored value and warns:
  "NAME has the same value as OTHER_NS/OTHER_NAME. If that was a paste
  mistake, replace it." The save still happens; nothing is stored about
  it, and values are never shown.
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
