# Features

Everything keydrop does, in one list. For the short version, see the [overview](index.md).

- **A web page for you.** Paste a value with a description of what it's
  for. You can view a value later (press "Show value"; every view is
  logged), replace it, roll back to the previous value, or delete it. Lists
  show names and descriptions only. The page is built for phones and uses no
  JavaScript. **Settings → Appearance** picks System, Light or Dark for each
  browser, and Settings also shows which build the server is running.
- **Admin login with a password, plus an authenticator code (TOTP) if you
  turn it on** (recommended, offered at setup with a QR code). Failed logins
  are rate-limited.
- **Namespaces and agent tokens.** Secrets live in namespaces (`homelab/…`,
  `media/…`). Each agent gets its own token, granted one or more
  namespaces. An agent can't see other namespaces at all, not even the secret
  names. Each token has a permission:
  - **read** (the default): use keys.
  - **add**: also create new keys, and replace the values of keys this same
    token created, until you save a value there yourself. It can't store
    variables.
  - **write**: create and replace anything in its namespaces.

  Tokens can be limited to the addresses they're used from. You pick a
  namespace from a list, and a new one is only made by choosing **+ New
  namespace…**, so a typo can't quietly create one. An agent's namespaces can
  be changed later on the **Agents** page. Revoking a token clears what it
  left pending; its open flags stay, marked *token since revoked*.
- **Pairing instead of pasting tokens.** `keydrop pair` on the agent's
  machine prints a link; you open it, check the code, choose what the agent
  may see, and approve. The agent collects its token directly.
- **Agent CLI.** `keydrop run -e NAME` puts a secret into one command's
  environment under its own name and masks it in the command's output.
  Secret names are env-var style (`CLOUDFLARE_API_TOKEN`), so nothing needs
  translating. `secrets`, `info` and `history` show descriptions, never values.
- **The CLI stays current.** The server hands out its own CLI build. When an
  agent's CLI is a different build, keydrop tells it what to do, at most once
  a day. With **Allow self-upgrade** on for that agent (it's off by default)
  that's `keydrop upgrade`, which replaces the binary with the server's build.
  With it off, the agent is told to leave that to you.
- **Variables for settings that aren't secret.** A URL, an account ID or a
  zone name can be stored as a *variable* next to the secrets. Variables
  are shown in full in the web page and to agents (`keydrop vars`,
  `keydrop get NAME`), aren't masked, and reading one isn't logged. They go
  into `run -e` exactly like secrets, so one command can take both. Only
  write tokens can store one, and other agents see it labelled as untrusted
  text until you save the value yourself.
- **Groups.** You can put keys in named, coloured groups (the **Groups**
  page, or a key's page). Keys not in a group are grouped by the part of
  the name before the first `_` when at least two share it (`CLOUDFLARE_TOKEN`
  and `CLOUDFLARE_ZONE` go under `CLOUDFLARE`); turn that off in Settings.
  Agents see the groups but can't make them or move keys between them.
- **Agents know what changed.** `keydrop history [NAME]` (run by a
  session-start hook) lists what happened to the keys the token can see,
  newest first, with who and when. `keydrop secrets --new` lists the values
  this token hasn't read since they changed.
- **Agents can ask for a key.** `keydrop request` creates an empty placeholder
  and returns a link for you to fill in, and `keydrop wait` blocks until you
  do. `keydrop request A B C --group NAME` asks for up to 10 keys at once: you
  fill them on one card, and can paste the file you downloaded (`key=value`
  lines) for keydrop to split by name. The group name is only a suggestion:
  nothing is grouped unless you tick the box.
- **Agents report problems; you decide what other agents read.**
  - `keydrop status NAME leaked` (or `ok`, `expired`, `revoked`,
    `replaced-by OTHER`) marks a key for everyone who can see it, with who
    set it and when. `keydrop run` and `get` warn on stderr when they hand
    out a key that isn't ok, but still run. You can set or clear it on the
    key's page; a status you set, agents can't change.
  - `keydrop flag NAME "reason" [--link URL]` puts the key on your
    **Inbox**. The reason and link are shown to you only (and go into the
    audit log); agents see "flagged by X on DATE".
  - `keydrop note NAME "text"` proposes a note and prints the link to
    approve it. Until you approve it (as written or edited) other agents see
    only "1 note awaiting approval". Descriptions an agent writes with `put`
    or `request` wait for your approval the same way, and stay marked as
    the agent's until you change the text.
  - The web page marks text an agent wrote as *agent-written*, and the CLI
    quotes it as untrusted text from another agent, so it reads as a claim
    and not an instruction.
- **Limits on agents.** So one agent can't flood you or the server:
  - a reason or link up to 500 characters (links http(s) only), a note up to
    2,000, and a variable up to 2,000 on one line, with no control or
    invisible formatting characters;
  - one open flag per token per key and 20 in all, and 20 open requests per
    token;
  - 60 flags, statuses and notes, and 200 puts and requests, per token an hour;
  - 500 keys and 8 MiB of values per token, not counting keys you've saved a
    value for yourself.

  History keeps 500 events per namespace, and a token flooding one evicts its
  own events first.
- **Expiry dates.** `keydrop expiring --check` exits non-zero when keys
  are about to expire, for health checks.
- **Tokens are rotated.** Each token is replaced on a schedule you pick
  when you approve or make it ("New token every"): 30, 90 (the default),
  180 or 365 days, or never. Near the end the agent asks for its new token
  by itself; you approve it with one tap in the **Inbox** and the agent
  swaps it in, so nothing else changes. From 30 days before the date every
  command warns on stderr, and `keydrop whoami` shows the date. A token past
  its date gets the same 401 as an unknown one. The **Agents** page shows when
  each token is due, and points out tokens unused for 30 days or more.
- **Renewal is a new token.** `keydrop renew` asks you to renew the token
  (also up to 30 days after it expired). You approve or decline it in the
  **Inbox**. Approving, or pressing **Rotate now** on the agent's page under
  Agents, replaces the token at once. The old one can then only collect the
  new one, only from the address that asked, within 7 days. The agent's next
  command does that by itself (or `keydrop renew --wait`), and saves the new
  token over the token file. A renewal not collected in 7 days revokes the
  token: pair the agent again. Nothing renews without you.
- **Canaries.** Pick **Canary** as the kind when you add one (or use
  **Make it a canary** on a secret's page) to make a decoy no agent should
  need. Leave the value empty and keydrop fills in a random one shaped
  like an API key. To agents it's an ordinary secret, and they see its
  description and usage, so write those as if it were real. Any agent call on
  it counts, even a refused one: reading it, writing it, flagging it, adding a
  note or setting a status. The log marks it *canary*, the **Inbox** shows one
  entry per canary and token until you dismiss it, and with an alert webhook
  set keydrop posts an alert, rate-limited so a burst can't flood the channel.

  Add the webhook in **Settings** (paste a Discord webhook URL; it's stored
  encrypted and never shown again), or set `KEYDROP_ALERT_WEBHOOK`. One added
  in Settings wins; removing it falls back to the variable. **Send test
  alert** says whether the webhook accepted it. Settings can also **revoke a
  token that reads a canary**. That's off by default, because the revocation
  tells whoever holds the token which secret was the canary. Variables can't
  be canaries.
- **Duplicate values.** When you save a value in the web page, keydrop
  compares it with every other stored value and warns: "NAME has the same
  value as OTHER_NS/OTHER_NAME. If that was a paste mistake, replace it." The
  save still happens, and values are never shown.
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
