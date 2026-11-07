# API

All endpoints except pairing take `Authorization: Bearer kd_…`, and an
optional `X-Keydrop-Agent: label`. A namespace the token isn't granted
returns 404, exactly like a missing secret. A token used from outside its
allowed sources gets 403. Flags, statuses and notes past their hourly limit
get 429, as do puts and requests past theirs, and a request past a token's
20 open ones.

| | |
|---|---|
| `GET /api/v1/whoami` | Token name, namespaces, `permission` (`read`, `add` or `write`), the older `write` flag, and `expires_at` (null: never) |
| `POST /api/v1/token/renew` | Ask the admin to renew this token → `{"state","expires_at","expired","created"}`; `state` is `pending`, `approved` (collect it), or `never` (it doesn't expire). Asking again changes nothing. Works for an expired token up to 30 days after expiry, and for a renewed one until the new token is used |
| `GET /api/v1/token/renew` | Where this token's renewal stands, same answer (`none` when there's no request; adds `collect_by` once approved) |
| `POST /api/v1/token/collect` | With the old token, once approved: `{"token","name","namespaces","expires_at"}`. Only from the address that asked (403 otherwise, logged and alerted); repeatable until the new token is first used; 401 after 7 days |
| `GET /api/v1/secrets?new=1&pending=1&namespace=x` | Metadata list (`kind` is `secret` or `variable`; a variable an agent wrote has `value_by`, naming that agent, and is untrusted text; variables include their `value`; `group` is `{"slug","name","color","auto"}` when the key is in one) |
| `GET /api/v1/secrets/{ns}/{name}` | Metadata, including `status`, open `flags` (who and when), approved `notes`, `pending_notes` and `description_pending`. `last_read_at`/`last_read_by` only when this token read it last |
| `POST /api/v1/secrets/{ns}/{name}/reveal?purpose=…` | `{"value": …}`, the only endpoint that returns a value (logged); adds `"status"` when the key isn't ok. Marks the value as no longer new to this token |
| `GET /api/v1/history?namespace=x&name=Y&limit=50` | Changes to the keys this token can see, newest first (at most 1000; 500 kept per namespace). Flag reasons aren't included |
| `POST /api/v1/secrets/{ns}/{name}/status` | `{"status","replaced_by"}`; `ok` clears it. 403 if the admin set the current status; `replaced_by` must exist in the namespace |
| `POST /api/v1/secrets/{ns}/{name}/flag` | `{"reason","link"}`. 409 if this token already has an open flag on the key. Flags in `GET` carry `token_revoked` when their token has since been revoked |
| `POST /api/v1/secrets/{ns}/{name}/notes` | `{"text"}` → 201 `{"url"}`, the page where the admin approves it |
| `POST /api/v1/secrets/{ns}/{name}/ack` | Deprecated (older CLIs): clears the *new* flag for this token; reveal does this now |
| `PUT /api/v1/secrets/{ns}/{name}` | `{"value","description","usage","expires","variable","overwrite"}` (add and write tokens; an add token can only replace keys it created and can't store variables; a variable from an agent is at most 2,000 characters on one line; a token holds at most 500 keys and 8 MiB of values, then gets 403; without `"variable": true` the value is stored as a secret, even over a variable). A description or usage from an agent waits for the admin's approval |
| `POST /api/v1/requests` | `{"namespace","name","description","usage"}` → `{"ref","url"}`. 409 if it already has a value, or another token already asked for it |
| `POST /api/v1/requests/batch` | `{"namespace","names","group","description","usage"}` → `{"refs","batch","url","urls"}`: up to 10 keys, filled on one card (`url` points at it). All or nothing; a batch of N counts as N requests towards the limits. `group` is a suggestion shown to the admin as agent-written |
| `GET /api/v1/expiring?days=14` | Secrets expiring within N days (at most 36500) |
| `POST /api/v1/pair` | No auth. `{"host","user"}` (shown to the admin, unchecked) → `{"code","path","link","poll","expires_in"}`. At most 3 waiting per address and 8 per IPv6 /64, 50 overall; when the list is full the busiest address's oldest request makes way for a newcomer |
| `POST /api/v1/pair/poll` | No auth. `{"poll"}` → `{"state":"pending"}`, or once approved `{"state":"approved","token","name","namespaces"}`, exactly once and only to the address that asked (403 from any other). 404 once expired, denied, collected, or the approved token was revoked |
| `GET /healthz` | No auth |
| `GET /setup.md` | No auth. The agent setup guide for this server, with the address it was fetched from and the certificate and key pins filled in (no token, no setup code). Same transport rules as `/install.sh` |
| `GET /install.sh` | No auth. Installer for Linux/macOS; downloads from the address it was fetched from (pinned to keydrop's key when that's keydrop itself). Only over https, or through a trusted proxy with an https `KEYDROP_PUBLIC_URL` |
| `GET /cli/keydrop-<os>-<arch>[.exe]`, `GET /cli/SHA256SUMS` | No auth. The CLI builds, same version as the server; 8 downloads at a time, 2 per address |

Authenticated responses carry `X-Keydrop-Version`, the server's build,
`X-Keydrop-Api-Level` and `X-Keydrop-Min-Cli-Level` (see below),
`X-Keydrop-Self-Upgrade` (`on` or `off`), and `X-Keydrop-Token-Expires`
(RFC 3339, or `never`).

**Keeping the CLI current.** The CLI sends `X-Keydrop-Cli-Level`; a request
without it counts as level 1. A CLI below the server's minimum level gets
426. A different build that still works gets one line on stderr, at most
once a day per server build, saying nothing breaks. What both say next
depends on the agent's **Allow self-upgrade** setting (Agents → the agent,
or when adding or approving one; off by default): on, run `keydrop
upgrade`; off, don't update it yourself, tell the user. `keydrop upgrade`
first asks the server (`POST /api/v1/cli/upgrade`, with the token, logged
as `cli.upgrade`) and stops if self-upgrade is off. Then it downloads the
server's build for this system from `/cli/` over the configured URL and
pin, checks it against `SHA256SUMS`, runs it once, and swaps it in,
keeping the old binary as `keydrop.<version>.bak`. The setting is
advisory: it decides what the agent is told and what `keydrop upgrade`
does, but a machine can always replace its own files. An expired or
replaced token gets 401 `invalid token`, like an unknown one, except on the
renewal endpoints.
