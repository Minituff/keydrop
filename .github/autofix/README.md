# The autofix routine

`.github/workflows/autofix.yml` hands unattended CI failures to a Claude Code
routine on claude.ai (see "When an unattended run fails" in
`docs/development.md`). The routine itself lives on claude.ai, so its setup is
recorded here to rebuild it. Nothing here is secret: the trigger URL and token
are the `CLAUDE_AUTOFIX_URL` and `CLAUDE_AUTOFIX_TOKEN` repository secrets.

## The routine

| Setting | Value |
|---|---|
| Repository | `Minituff/keydrop` only (on the routine, not the environment) |
| Prompt | `prompt.md`, pasted in full. Paste it again after changing it here. |
| Model | Opus |
| Connectors | None. Remove every connector it adds by default. |
| Trigger | API. Its URL and token go in the two secrets above. |
| Auto-fix pull requests | Off: anyone can comment on a public repo's PR |
| Branch pushes | The default, `claude/*` only |

## The environment

Its own cloud environment, `keydrop-autofix`, not shared with anything else.

| Setting | Value |
|---|---|
| Repositories | None (the routine picks the repo) |
| Environment variables | None |
| Network access | Custom, without the default list (it includes storage hosts anyone can write to) |

Allowed domains:

```
proxy.golang.org
sum.golang.org
index.golang.org
golang.org
go.dev
pkg.go.dev
dl.google.com
github.com
api.github.com
codeload.github.com
raw.githubusercontent.com
objects.githubusercontent.com
release-assets.githubusercontent.com
ghcr.io
pkg-containers.githubusercontent.com
gcr.io
registry-1.docker.io
auth.docker.io
production.cloudflare.docker.com
pypi.org
files.pythonhosted.org
archive.ubuntu.com
security.ubuntu.com
```

Setup script. The image's Go is older than `go.mod` needs, and Go's own
toolchain download comes from `storage.googleapis.com`, which isn't allowed,
so this installs the newest Go from `dl.google.com`:

```bash
#!/bin/bash
set -euo pipefail
v=$(curl -fsSL 'https://go.dev/VERSION?m=text' | head -n 1)
case $(uname -m) in aarch64|arm64) a=arm64 ;; *) a=amd64 ;; esac
rm -rf /usr/local/go
curl -fsSL "https://dl.google.com/go/$v.linux-$a.tar.gz" | tar -C /usr/local -xz
ln -sf /usr/local/go/bin/go /usr/local/bin/go
ln -sf /usr/local/go/bin/gofmt /usr/local/bin/gofmt
go version
```

## Testing it

Actions → **autofix** → Run workflow, with text such as `Mode: report. A test,
not a real failure: open an issue titled "autofix: test" saying you got this,
then stop.` The run's log should say `Handed off: HTTP 200`.
