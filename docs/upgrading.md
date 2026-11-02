# Upgrading and rolling back

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

**The alert webhook added in Settings** is a newer field too. The
release before it starts on the data and uses `KEYDROP_ALERT_WEBHOOK` (or
none); once it saves, the webhook is gone from the file, so add it again
in Settings after rolling forward. `downgrade-data` isn't needed for it.

**Token expiry, renewal and canaries are different.** Once any of them is
in use (and a token made with the default lifetime counts), the sealed key
check records that their integrity check is required, so the file can't
be rolled back by deleting those fields. The release before them then
refuses the data ("master key does not match this data directory") until
you run `downgrade-data` with this release, the server stopped:

```sh
docker compose run --rm keydrop downgrade-data
```

It goes back one format at a time and lists by name what it drops:

- **expiry:** every token stops expiring;
- **renewal requests** waiting in the Inbox;
- **renewals approved but not collected:** those tokens are deleted (the
  old token no longer works and the new one was never handed over), so
  pair those agents again. Collected renewals are kept: only the new
  token works;
- **canaries:** the flag on each secret, the Inbox's canary entries (the
  audit log keeps them), and "revoke a token that reads a canary".

Then switch `image:` back and start the older image. This release still
starts on that data and picks the features up again when you use them.
To go back past the integrity check as well, run `downgrade-data` a
second time.

## Rotating the TLS certificate

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
