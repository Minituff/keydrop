# Installing the server by hand

The [agent setup guide](agent-setup.md) does all of this for you. These are the same steps, done by hand.

## Verify the image

Use a released version, not `latest`, and check that the image is the one
keydrop's release workflow built before you run it. Pick the newest version
on the [releases page](https://github.com/Minituff/keydrop/releases) and put
it in `version` (without the `v`). The check needs the
[GitHub CLI](https://cli.github.com/), signed in with `gh auth login`.

```sh
version=1.2.3
docker pull "ghcr.io/minituff/keydrop:$version"
image=$(docker inspect --format '{{index .RepoDigests 0}}' "ghcr.io/minituff/keydrop:$version")
gh attestation verify "oci://$image" --repo Minituff/keydrop \
  --signer-workflow Minituff/keydrop/.github/workflows/release.yml \
  --source-ref "refs/tags/v$version"
echo "$image"
```

If `gh attestation verify` fails, **stop**: don't run that image. If it
passes, `$image` is that exact image, pinned by its digest
(`ghcr.io/minituff/keydrop@sha256:…`). The steps below use it, so run them
in the same terminal.

## Start the server

```sh
mkdir keydrop && cd keydrop
mkdir data && sudo chown 65532:65532 data
# Generate a key only for a new installation.
if ( umask 077; set -C; docker run --rm "$image" genkey > master.key ) && [ -s master.key ]; then
  sudo chown 65532:65532 master.key && sudo chmod 400 master.key
else
  echo "Key generation failed or master.key already exists. Stop and investigate."
fi
```

If key generation or either `sudo` command fails, **stop** before starting the server.
An existing `master.key` is left untouched. A failed first attempt may leave
an empty or incomplete file; inspect the situation before removing it and
trying again. Never replace the key for an existing installation.

Once the key is ready:

```sh
curl -O https://raw.githubusercontent.com/minituff/keydrop/main/compose.example.yml
# set image: to the $image you checked, edit KEYDROP_PUBLIC_URL and
# KEYDROP_TLS_HOSTS, then:
docker compose -f compose.example.yml up -d
docker logs keydrop
```

Pin the image by its digest in the compose file, so a restart always runs
the image you checked:

```yaml
    image: ghcr.io/minituff/keydrop:1.2.3@sha256:…
```

The version before `@` is only for you to read; Docker uses the digest. To
upgrade, check the new version the same way and put its digest there (see
[Upgrading and rolling back](upgrading.md)).

The log prints two things:

1. **A one-time setup code** (6 characters, like `K7Q-MP3`), and a link
   with the code filled in. Go to `/setup`, enter the code, and choose a
   password. The code only proves you can read the log, so nobody else on
   the network can claim the empty install first. Then add keydrop to an
   authenticator app (scan the QR code, or on a phone tap "Add to
   authenticator app"), or choose password only and add one later in
   Settings.
2. **The certificate pin** (`KEYDROP_TLS_PIN=sha256:…`). Agents need this.

## The master key

keydrop encrypts everything with this key, and never writes it to `data/`.
`genkey` writes a random key straight to `master.key` without displaying it.
Compose mounts that file at `/run/secrets/keydrop_master_key`, and keydrop
reads it there on every start.

- **Make it once.** The commands above won't replace an existing
  `master.key`. Don't generate a new one for a server that's in use: a new key
  can't read the old data.
- **Use the same file on every start.** If you move the server, move
  `master.key` with `data/`.
- **Back it up away from `data/`.** In a private terminal, run
  `sudo cat master.key` and copy the line into your password manager. Don't
  paste it into a chat or give it to an agent. Someone with both the key and
  `data/` can read every value.
- **To restore it,** put the saved line back in `master.key`, then run
  `sudo chown 65532:65532 master.key && sudo chmod 400 master.key`.
- **If you lose it,** nothing stored can be recovered, and there's no reset.
  You'd start again with a new key and an empty `data/`.
- **If it leaks,** and someone may also have a copy of `data/`, treat every
  value as exposed. keydrop can't change the key of existing data, so start a
  new server with a new key, and replace each value where it was issued.

More on [what it protects](security.md#what-the-master-key-protects).

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
| `KEYDROP_RESET_ADMIN` | `false` | Reopen setup to replace the admin password and authenticator. **Remove it once setup is done, and restart:** while it's set, every restart reopens setup and logs a new setup code, so anyone who can read the log could replace the admin login. keydrop logs a warning while it's set. |
| `KEYDROP_CLI_DIR` | `/cli` in the image | Where the CLI builds the server hands out live (`keydrop-<os>-<arch>.gz` plus `SHA256SUMS`). Unset outside the image: no downloads. |
| `KEYDROP_ALERT_WEBHOOK` | — | URL that canary alerts (and refused renewal collects) are POSTed to as `{"content": "…"}` (Discord-compatible). Sent in the background with a 5 s timeout. Alerts name the secret, token, address and time, never a value or token. The URL itself is a credential: it's never logged or shown, only where it posts. A webhook added in Settings is used instead. |

CLI: `KEYDROP_URL`, `KEYDROP_TOKEN` / `KEYDROP_TOKEN_FILE`, `KEYDROP_TLS_PIN`
override the files written by `keydrop pair` / `keydrop login`. A pin
needs an `https://` URL; with `http://` the CLI refuses rather than skip
the check.
`KEYDROP_AGENT` sets the agent label shown in the log.

## Behind a reverse proxy

keydrop serves HTTPS itself. With a reverse proxy in front, either point it
at `https://keydrop:8443` and turn off certificate verification for that hop
(in Traefik, a `serversTransport` that skips it), or set `KEYDROP_TLS=off` and
keep the hop on a private Docker network. Set `KEYDROP_TRUSTED_PROXIES` to the
proxy's IP. The proxy must send `X-Forwarded-Proto: https`; without it keydrop
won't serve `/install.sh` or `/setup.md` through the proxy, since it can't
tell the client didn't use plain http. Agents can still talk to the
container directly with the pinned certificate, so they don't depend on the
proxy or DNS.

**Don't expose keydrop to the internet.** Reach it over your LAN or a VPN
such as Tailscale or WireGuard.
