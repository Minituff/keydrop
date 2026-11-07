# Security

## What it's for, and what it isn't

**It protects against accidents:** a key pasted into chat (and stored in the
provider's transcript), echoed into a tool's output, saved in shell history,
committed in a `.env` file, or left in plaintext on disk.

**It doesn't protect against a malicious or compromised agent.** Anything that
can *use* a secret can exfiltrate it. keydrop makes sure an agent doing normal
work never sees values. It doesn't make that impossible, and nothing that
hands secrets to a program can.

It's built for one person and a few agents on a home network. It isn't a
replacement for Vault or Infisical in a team.

## Security design

| | |
|---|---|
| At rest | Each value is encrypted with AES-256-GCM. The AAD binds the ciphertext to the secret's name, so values can't be swapped between records. The TLS private key is sealed the same way, and `keydrop.json` carries an HMAC (key derived from the master key), so edits made without the master key stop keydrop from starting. The master key comes from a file (Docker secret) and is never stored in the data directory. See [what the master key protects](#what-the-master-key-protects). |
| Agent tokens | 256-bit random, stored as SHA-256 hashes, shown once. They start with `kd_` so they're easy to grep for if they leak. Each can be limited to allowed source addresses, and is replaced on a schedule (unless set to never). |
| Renewal | Approved by the admin only. Approval replaces the token; the new one is kept sealed with the master key until the agent collects it with the old token, from the address that asked, within 7 days. The Inbox flags a request made from an address other than the token's last one; a collect from another address is refused, logged and alerted. |
| Pairing | The admin approves each machine in the UI. The token is handed over once, only to the address that asked, and a token approved but never collected is revoked after 10 minutes, even across a restart. Pairing and renewal are the only ways a token is handed to an agent. |
| Admin password | PBKDF2-HMAC-SHA256, 600,000 iterations. Optional TOTP; codes can't be replayed. |
| Login limits | 5 failures per client and 20 overall per 15 minutes; each attempt is counted before the password is checked, so parallel guesses don't get extra tries. A browser that has logged in before carries a signed device cookie and is exempt from the overall limit, so failures from elsewhere on the network can't lock the owner out. |
| Sessions | `__Host-` cookie, `HttpOnly`, `SameSite=Strict`, 1 h idle and 8 h maximum, kept in memory (a restart logs everyone out). Each page reloads itself (meta refresh, no JavaScript) just after its session would end, so it lands on the login page instead of looking logged in. CSRF token on every form, and cross-site requests (`Sec-Fetch-Site`) are refused. |
| Headers | Strict CSP (no scripts at all), `X-Frame-Options: DENY`, `no-referrer`, `no-store`. |
| Transport | TLS by default with a self-signed certificate. The CLI pins its SHA-256 fingerprint, so there's no public CA and no DNS dependency. |
| Container | distroless (no shell), non-root, read-only filesystem and no capabilities in the example compose file. |

## What the master key protects

Someone with a copy of `data/` but not the master key can't:

- read any secret or variable value, or the authenticator seed;
- read the TLS private key (`tls.key` is sealed), so they can't pose as
  the server that agents have pinned. **The exception** is a copy made after
  `keydrop downgrade-data`, or before `keydrop upgrade-data`, which holds
  `tls.key` in plaintext. If such a copy may have been exposed,
  [rotate the certificate](upgrading.md#rotating-the-tls-certificate);
- change `keydrop.json` (add a token hash, replace the admin password,
  grant a namespace) and have keydrop start on it: its HMAC no longer
  matches and keydrop refuses to start with an integrity error. Removing
  the HMAC and pasting in an older key check doesn't get around it either:
  keydrop refuses older-format data outright and never upgrades it on its
  own. Only the operator can, with `keydrop upgrade-data`, so only run that
  on data you know is your own and unedited.

They **can** still see metadata: secret and variable names, descriptions,
namespaces, token names, the admin password's PBKDF2 hash, and the audit
log. And someone who can write to `data/` can put back an **older complete
copy** of it in the current format (a backup verifies fine, bringing
back revoked tokens or an old password), or delete it. Protect `data/` like any other backup, just not like the key.

Limitations, by design for now:

- **No master-key rotation.** Changing the key means a new install and
  re-entering the values.
- **One server per data directory.** There's no lock file: two instances
  on one volume would overwrite each other's changes. Run one.
