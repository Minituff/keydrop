# Features

Everything keydrop does. For the short version, see the [overview](index.md).

## The web page

Paste a value with a description of what it's for. Later you can:

- view it (press **Show value**; every view is logged),
- replace it, roll back to the previous value, or delete it.

Lists show names and descriptions only, never values. The page is built for
phones and uses no JavaScript. **Settings → Appearance** picks System, Light
or Dark for each browser, and Settings also shows which build the server is
running.

## Signing in

You sign in with a password, plus an authenticator code (TOTP) if you turn it
on. It's recommended, and offered at setup with a QR code. Failed logins are
rate-limited.

## Namespaces and tokens

Secrets live in namespaces, like `homelab/…` or `media/…`. Each agent gets its
own token, granted one or more namespaces, and can't see any other namespace
at all, not even the secret names.

Each token has a permission:

| Permission | What the agent can do |
|---|---|
| **read** (the default) | Use keys. |
| **add** | Also create new keys, and replace the values of keys this same token created, until you save a value there yourself. It can't store variables. |
| **write** | Create and replace anything in its namespaces. |

- **Allowed addresses.** A token can be limited to the addresses it's used
  from. From anywhere else it's refused.
- **No typo namespaces.** You pick namespaces from a list. A new one is only
  made by choosing **+ New namespace…**.
- **Changing an agent.** Its namespaces, permission and settings can be
  changed later on the **Agents** page.
- **Revoking.** Revoking a token clears what it left pending. Its open flags
  stay, marked *token since revoked*.

## Pairing

`keydrop pair` on the agent's machine prints a link. You open it, check the
code, choose what the agent may see, and approve. The agent collects its token
directly, so you never copy a token around.

## The agent CLI

- **`keydrop run -e NAME`** puts a secret into one command's environment under
  its own name, and masks it in the command's output. Names are env-var style
  (`CLOUDFLARE_API_TOKEN`), so nothing needs translating.
- **`secrets`, `info` and `history`** show descriptions, never values.
- **It stays current.** The server hands out its own CLI build. When an
  agent's CLI is a different build, keydrop tells it what to do, at most once a
  day. With **Allow self-upgrade** on for that agent (it's off by default),
  that's `keydrop upgrade`, which replaces the binary with the server's build.
  With it off, the agent is told to leave that to you.

## Variables

A URL, an account ID or a zone name can be stored as a *variable* next to the
secrets. Unlike secrets, variables:

- are shown in full, in the web page and to agents (`keydrop vars`,
  `keydrop get NAME`),
- aren't masked, and reading one isn't logged.

They go into `run -e` exactly like secrets, so one command can take both. Only
write tokens can store one, and other agents see it labelled as untrusted text
until you save the value yourself.

## Groups

You can put keys in named, coloured groups, on the **Groups** page or a key's
page. Keys not in a group are grouped by the part of the name before the first
`_` when at least two share it: `CLOUDFLARE_TOKEN` and `CLOUDFLARE_ZONE` go
under `CLOUDFLARE`. You can turn that off in Settings. Agents see the groups
but can't make them or move keys between them.

## What agents learn, and what they can ask

- **What changed.** `keydrop history [NAME]` lists what happened to the keys
  the token can see, newest first, with who and when. It's made to run from a
  session-start hook. `keydrop secrets --new` lists the values this token
  hasn't read since they changed.
- **Asking for a key.** `keydrop request` creates an empty placeholder and
  returns a link for you to fill in, and `keydrop wait` blocks until you do.
- **Asking for several.** `keydrop request A B C --group NAME` asks for up to
  10 keys at once. You fill them on one card, or paste the file you downloaded
  (`key=value` lines) and keydrop splits it by name. The group name is only a
  suggestion: nothing is grouped unless you tick the box.

## Agents report problems; you decide what others read

- **Status.** `keydrop status NAME leaked` (or `ok`, `expired`, `revoked`,
  `replaced-by OTHER`) marks a key for everyone who can see it, with who set it
  and when. `keydrop run` and `get` warn on stderr when they hand out a key
  that isn't ok, but still run. You can set or clear it on the key's page, and
  agents can't change a status you set.
- **Flags.** `keydrop flag NAME "reason" [--link URL]` puts the key in your
  **Inbox**. The reason and link are shown to you only, and go into the audit
  log. Agents see "flagged by X on DATE".
- **Notes.** `keydrop note NAME "text"` proposes a note and prints the link to
  approve it. Until you approve it, as written or edited, other agents only see
  "1 note awaiting approval". Descriptions an agent writes with `put` or
  `request` wait for your approval the same way, and stay marked as the
  agent's until you change the text.
- **Agent text is marked.** The web page marks it *agent-written*, and the CLI
  quotes it as untrusted text from another agent, so it reads as a claim and
  not an instruction.

## Limits on agents

So one agent can't flood you or the server:

| What | Limit |
|---|---|
| A flag's reason or link | 500 characters, links http(s) only |
| A note | 2,000 characters |
| A variable an agent stores | 2,000 characters, on one line |
| Open flags | One per token per key, and 20 per token |
| Open requests | 20 per token |
| Flags, statuses and notes | 60 per token an hour |
| Puts and requests | 200 per token an hour |
| Stored values | 500 keys and 8 MiB per token, not counting keys you've saved yourself |

Agent text can't contain control or invisible formatting characters. The
history keeps 500 events per namespace, and a token flooding one evicts its own
events first.

## Expiry and token rotation

- **Expiry dates.** `keydrop expiring --check` exits non-zero when keys are
  about to expire, for health checks.
- **Rotation schedule.** Each token is replaced on a schedule you pick when you
  approve or make it ("New token every"): 30, 90 (the default), 180 or 365
  days, or never.
- **Renewing itself.** Near the date, the agent asks for its new token by
  itself. You approve it with one tap in the **Inbox**, and the agent swaps it
  in, so nothing else changes. You can also decline, or press **Rotate now** on
  the agent's page.
- **Warnings.** From 30 days before the date, every command warns on stderr,
  and `keydrop whoami` shows the date. The **Agents** page shows when each
  token is due, and points out tokens unused for 30 days or more.
- **After the date.** A token past its date gets the same 401 as an unknown
  one. `keydrop renew` can still ask for 30 days after.
- **Collecting the new token.** Once you approve, the old token can only
  collect the new one, only from the address that asked, within 7 days. The
  agent's next command does that by itself (or `keydrop renew --wait`) and
  saves the new token over the old one. A renewal not collected in 7 days
  revokes the token, and you pair the agent again. Nothing renews without you.

## Canaries

A canary is a decoy key no agent should need. Pick **Canary** as the kind when
you add one, or press **Make it a canary** on a secret's page.

- **It looks real.** Leave the value empty and keydrop fills in a random one
  shaped like an API key. To agents it's an ordinary secret, and they see its
  description and usage, so write those as if it were real. Variables can't be
  canaries.
- **Any call counts,** even a refused one: reading it, writing it, flagging it,
  adding a note or setting a status.
- **You find out.** The log marks it *canary*, and the **Inbox** shows one
  entry per canary and token until you dismiss it.
- **Alerts.** With an alert webhook set, keydrop posts an alert, rate-limited
  so a burst can't flood the channel. Add a Discord webhook URL in
  **Settings** (it's stored encrypted and never shown again), or set
  `KEYDROP_ALERT_WEBHOOK`. One added in Settings wins, and removing it falls
  back to the variable. **Send test alert** says whether the webhook accepted
  it.
- **Revoking on touch.** Settings can also revoke a token that reads a canary.
  It's off by default, because the revocation tells whoever holds the token
  which secret was the canary.

## Duplicate values

When you save a value in the web page, keydrop compares it with every other
stored value and warns: "NAME has the same value as OTHER_NS/OTHER_NAME. If
that was a paste mistake, replace it." The save still happens, and values are
never shown.

## Audit log

Every login, change and secret read is logged: which agent, which secret,
which command, and whether `run --no-mask` was used. A secret read that can't
be written to the log doesn't happen. The **Log** page shows it all, newest
first.

| File | Holds | Rotation |
|---|---|---|
| `data/audit.jsonl` | Everything that needs a login or a token | At 10 MiB, five old copies (`.1` to `.5`, about 60 MiB in all) |
| `data/audit-unauth.jsonl` | Events anyone on the network can cause: a bad token, a pairing request, a locked login | At 10 MiB, one old copy |

The second file keeps a flood of those events from pushing the record of who
read what off the disk. They're logged at most once a minute per address and
60 a minute overall, with a count of what was left out. Text fields are cut at
200 bytes.
