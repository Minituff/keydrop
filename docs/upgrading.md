# Upgrading and rolling back

## Updating keydrop

With Compose (data in `./data`, as in `compose.example.yml`):

1. Read the release notes. If a release needs an extra step, they say so.
2. Stop keydrop and back up `data/`, keeping the copy as safe as the original:
   ```sh
   docker compose stop keydrop
   sudo cp -a data data.bak-$(date +%F)
   ```
3. Check the new version's image as in
   [Verify the image](install.md#verify-the-image), point `image:` at the
   digest it printed, then `docker compose pull keydrop`.
4. Start it with `docker compose up -d keydrop`. `docker logs keydrop` should
   show the same `KEYDROP_TLS_PIN=sha256:…` as before.
5. On an agent, `keydrop whoami` should work without changes.

The server carries the CLI for its own version, so agents' CLIs follow it.
keydrop tells each agent when its CLI is a different build. If you allowed
that agent to upgrade itself, it runs `keydrop upgrade`; if not, it tells you,
and you can reinstall the CLI with the command on the **Agents** page.

## Rolling back

Stop keydrop, put the backup of `data/` from step 2 back, switch `image:`
back and start it. Anything changed since the backup is lost, and whatever
you revoked or replaced since then comes back: revoked tokens work again, and
an old admin password does too. If that matters, revoke those tokens and
change the password again.

## Rotating the TLS certificate

Do this if keydrop's TLS private key may have leaked: a plaintext copy of
`tls.key`, or a copy of `data/` together with the master key. With the server
stopped and the same volumes and environment (`KEYDROP_TLS_HOSTS` sets the new
certificate's names, as on first start):

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

## Lost the admin password or authenticator

Restart with `KEYDROP_RESET_ADMIN=true`, use the new setup code, then remove
the variable and restart again. Secrets and tokens are kept. Don't leave it
set: every restart would reopen setup and log a new setup code, and anyone
who can read the log could then replace the admin login. keydrop logs a
warning at start while it's set, and a reminder once setup is done. To change the password while
logged in, use **Settings → Password**; that logs out every other browser.

## Upgrading from a development build

You only need this if your data was written by a build from before the first
release. keydrop then won't start, and says to run `keydrop upgrade-data`.
It doesn't upgrade by itself: the old format has no integrity check, so
upgrading vouches for the files exactly as they are, and that's your decision.
Only do it on data you know is your own and unedited.

Stop keydrop, back up `data/`, and run this with the new image and the same
volumes, secret and user. The backup holds `tls.key` in plaintext, so keep it
as safe as the master key:

```sh
docker compose run --rm keydrop upgrade-data
```

It adds the integrity check and seals `tls.key`. The key and certificate stay
the same, so **the pin agents hold doesn't change**. If an older copy of
`data/` may have been exposed, [rotate the certificate](#rotating-the-tls-certificate).

`keydrop downgrade-data` goes the other way, one format per run, for going
back to such a build. It lists by name what it drops, and it writes `tls.key`
back in plaintext. Neither command is in `keydrop help`.
