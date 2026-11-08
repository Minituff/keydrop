# The autofix routine

`.github/workflows/autofix.yml` hands unattended CI failures to a Claude Code
routine on claude.ai (see "When an unattended run fails" in
`docs/development.md`). The routine itself lives on claude.ai, so its setup is
recorded here to rebuild it. Nothing here is secret: the trigger URL and token
are the `CLAUDE_AUTOFIX_URL` and `CLAUDE_AUTOFIX_TOKEN` secrets in the
repository's `autofix` environment, which only `main` may use.

## The live version

The routine uses the prompt and setup script with these sha256 sums. After
changing either file, paste it into the routine (or the environment) on
claude.ai and put its new sum here, in the same commit:
`scripts/autofix-check.sh` fails CI while a file and its sum differ.

```
f3bc13e6c3b074bb0d06aa600b8931dd2d784220413c8ab194b887795e22a5c4  prompt.md
2009431f8e4d0ee1a8ea41bb2c55d46bb756c5b685f67b5270634d44fc2d55d5  setup.sh
```

## The routine

| Setting | Value |
|---|---|
| Repository | `Minituff/keydrop` only (on the routine, not the environment) |
| Prompt | `prompt.md`, pasted in full |
| Model | Opus |
| Connectors | None. Remove every connector it adds by default. |
| Trigger | API. Its URL and token go in the two secrets above. |
| Auto-fix pull requests | Off: anyone can comment on a public repo's PR |
| Branch pushes | `claude/*` is only Claude's default and its prompt: the proxy lets a push update any branch |

The workflow sends only fixed text: the mode, the failed run's metadata and a
marker for the duplicate check, or a test message when started by hand.
Everything the routine opens carries the `autofix` label (create it once in
the repository's labels) and that marker.

## The environment

Its own cloud environment, `keydrop-autofix`, not shared with anything else.

| Setting | Value |
|---|---|
| Repositories | None (the routine picks the repo) |
| Environment variables | None |
| Network access | Custom, without the default list (it includes storage hosts anyone can write to) |
| Setup script | `setup.sh`, pasted in full |

Allowed domains:

```
go.dev
dl.google.com
raw.githubusercontent.com
github.com
api.github.com
pypi.org
files.pythonhosted.org
archive.ubuntu.com
security.ubuntu.com
```

What each is for: `go.dev` lists Go's releases with their sha256 and
`dl.google.com` serves them (the setup script); `raw.githubusercontent.com`
serves `go.mod` when the setup runs before the repository is cloned; `github.com`
and `api.github.com` are git and `gh api`; PyPI is for running the `docs`
workflow's `pip install mkdocs-material` and `mkdocs build`; the Ubuntu hosts
are for `apt-get` when a tool is missing from the image.

There's no Go module proxy or checksum database on the list: keydrop has no Go
modules, and the setup script sets `GOTOOLCHAIN=local`, `GOPROXY=off` and
`GOSUMDB=off` so Go never asks for one. Nor are there container registries:
the routine doesn't build the image (CI's `image` job does).

The list keeps the routine from pulling code and tools from places nobody
vetted. It doesn't stop data leaving: GitHub is on it, and anything the
routine writes to a branch, PR or issue of a public repository is public.
What keeps secrets out of its reach is that it has none: no environment
variables, no connectors, and keydrop's tests use made-up values.

The setup script installs the Go version in `go.mod`'s `toolchain` line (from
the checkout, or from `main` when it runs before the clone), checks the
download against the sha256 go.dev publishes, and puts it in
`/usr/local/go`. The image's own Go is older than `go.mod` needs, and Go's
toolchain download comes from `storage.googleapis.com`, which isn't allowed.

## Testing it

Actions → **autofix** → Run workflow. It sends a fixed test message; the
routine should open an issue titled `autofix: test` with the `autofix` label.
The run's log should say `Handed off: HTTP 200`. The checks before the hand-off
apply to tests too: one a day (UTC) gets through, and not while the last test
issue is open, so close it afterwards.
