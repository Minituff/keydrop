# Installing the server by hand

The [agent setup guide](agent-setup.md) does all of this for you. These are the same steps, done by hand.

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

Keep the master key safe: [what it protects](security.md#what-the-master-key-protects).

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
| `KEYDROP_ALERT_WEBHOOK` | — | URL that canary alerts (and refused renewal collects) are POSTed to as `{"content": "…"}` (Discord-compatible; Slack and ntfy accept it too). Sent in the background with a 5 s timeout. Alerts name the secret, token, address and time, never a value or token. The URL itself is a credential: it's never logged or shown, only where it posts. A webhook added in Settings is used instead. |

CLI: `KEYDROP_URL`, `KEYDROP_TOKEN` / `KEYDROP_TOKEN_FILE`, `KEYDROP_TLS_PIN`
override the files written by `keydrop pair` / `keydrop login`. A pin
needs an `https://` URL; with `http://` the CLI refuses rather than skip
the check.
`KEYDROP_AGENT` sets the agent label shown in the log.

## Behind a reverse proxy

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
