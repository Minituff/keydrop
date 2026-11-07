# AGENTS.md — working on keydrop

Instructions for AI coding agents (Claude Code, Codex, others) and humans
working on this repo. Before changing code, read the page in
[`docs/`](docs/) that covers it (table below).

keydrop holds other people's API keys. Treat every change as
security-sensitive: a small convenience that weakens one of the rules below
isn't worth it.

## Docs — read before touching the code they cover

| Page | Read it before changing | Covers |
|---|---|---|
| [docs/design_doc.md](docs/design_doc.md) | Any behaviour: `internal/store`, `internal/auth`, `internal/server` (API, pairing, TLS), `cmd/keydrop`, the data format | The design, the reasons behind it, and what's planned |
| [docs/ui.md](docs/ui.md) | Anything in `internal/server/web/` (`style.css`, templates) or UI handlers in `ui.go` | Light/dark palette, components, phone layout, how to check a page |
| [docs/agent-setup.md](docs/agent-setup.md) | The agent setup flow, `setup.go`, `agent-setup.md.tmpl`, CLI commands agents use | Setting up keydrop with an AI agent (part of it is generated; see Conventions) |

Keep them current: a change that makes a page wrong updates that page in the
same commit. New areas that need more than a README line get their own page
here and a row in this table.

The other pages in `docs/` are for **people** deciding whether to run keydrop
and setting it up: `features.md`, `security.md`, `install.md` (including the
configuration table), `pairing.md`, `upgrading.md`, `api.md` and
`development.md`. They're also the MkDocs site (`mkdocs.yml`, built by the
`docs` workflow, published only by hand). Write them in plain words for a
human; keep the README short and link to them. `docs/index.md` is generated
from `README.md`: after editing the README run `sh scripts/docs-index.sh`
(CI fails while they differ). Screenshots in `docs/images/` show only
made-up data.

## Security invariants — don't break these

- **Secret values are only shown on purpose, and every view is logged.** In
  the web UI a secret appears only after the admin presses "Show value" (a
  POST with the CSRF token), never in a list, a URL or a redirect. Agents
  get secrets only from `POST /api/v1/secrets/{ns}/{name}/reveal` with a
  token. Both are audit-logged, and those are the only two ways a secret
  leaves the server. **Variables** (`Secret.Variable`) are the deliberate
  exception: their values appear in lists and API responses, reads aren't
  logged, and `run` doesn't mask them. Any code that shows a value must
  check the kind, via `store.VariableValue`, which refuses secrets.
- **Never log, print or return a value or token** anywhere else: not in
  logs, errors, audit entries, templates or test output. Errors
  name the secret (`ns/name`), never its contents.
- **Namespace isolation.** A secret in a namespace the token isn't granted
  returns **404**, identical to a missing secret, so names don't leak. Every
  new API endpoint must go through the same grant check.
- **Agents never get admin rights.** Tokens can't create tokens, change
  grants, or reach the UI. Pairing only *asks*: a token exists only after
  the admin approves in the UI.
- **Every token check goes through `store.LookupToken`** (in the server,
  `agentAuth`), which enforces allowed sources, expiry and rotation.
  Don't add a second way to authenticate a token. An expired or replaced
  token gets the same 401 as an unknown one. An expired token may call
  only the renewal endpoints (`/api/v1/token/renew`, `/api/v1/token/collect`),
  and only within `RenewalGrace`; a replaced one only those too. The only
  unauthenticated API endpoints are `/api/v1/pair` and `/api/v1/pair/poll`;
  keep them capped.
- **Pairing and renewal are the only ways a token is handed over.** Both
  need the admin's approval in the UI, and both hand the token only to the
  address that asked. A renewed token is sealed under the master key until
  collected; it's never stored in plaintext or shown to the admin. The CLI
  writes a collected token atomically (lock, temp file, fsync, rename) and
  never prints it.
- **A canary is indistinguishable to agents.** No API response, error,
  header or code path may differ between a canary and an ordinary secret
  as seen by the token. Every agent call on one (read, write, status, flag,
  note) is a touch; agents can't clear the flag.
- **The alert webhook URL is a credential.** Never log, show or return it,
  and never put a value or a token in an alert body. Alerts go through the
  one `alerter` (rate-limited, async); don't add another sender.
- **Encryption at rest:** AES-256-GCM per value, with the namespace, name and
  field bound as additional data. The master key is never written to the
  data directory. `tls.key` is sealed too, and `keydrop.json` is HMAC'd
  with a key derived from the master key (`Store.DeriveKey`; never reuse
  the encryption key for anything else). Any change to the data format
  needs a migration, a way back (`keydrop downgrade-data`) and a README
  note under "Upgrading and rolling back". The server never upgrades
  data on start: a format the HMAC doesn't cover is refused, and the
  operator migrates it with `keydrop upgrade-data` (otherwise anyone who
  can write the data directory could get an edited old-format file
  vouched for by restarting the server).
- **Optional fields need no migration, but must keep the previous
  release reading the file.** `mac` covers `legacyView()` (the 038a737
  format), `mac2` covers `v2View()` (the 733cf9f format, which checks
  `mac2` over everything it parses), `mac3` covers
  `v3View()` (the b0b9efe format), `mac4` covers `v4View()` (the 7b184c1
  format), `mac5` covers `v5View()` (the cf00c92 format) and `mac6` covers
  everything. A new optional field goes outside every older view. This
  release checks `mac6` over all it parses, so once it has shipped, the
  next new field needs a `v6View` that zeroes it and a seventh MAC, the
  same way `v5View`/`mac6` were added. Never add a plain new field an existing
  MAC covers. A field that restricts access (like expiry, rotations,
  canaries) must not be strippable: tie it to a sealed key check the way
  `keyCheckV4` does, so only `downgrade-data` can remove it. Each gets a case in
  `TestOlderReleaseReadsNewerFile`. The e2e suite starts the older
  releases (`rollbackCommit` through `v5RollbackCommit`) on data this one wrote. A fix-up of data the
  previous release wrote goes in `Store.fixup` (bump `fixupVersion`), runs
  only on a file whose MAC verified, and may change only what that
  release could also have written, or `ext`.
- **Agent text is untrusted.** Anything an agent writes that other agents
  read (notes, descriptions) waits for the admin's approval; flag text is
  for the admin only. Escape it in HTML, mark it as agent-written, and
  quote it in the CLI. New agent-writable fields need a size limit, the
  `checkText` character check (no control or Cf characters), and a
  per-token rate limit (`annotations` or `writes`); anything an agent can
  add to the state needs a per-token cap too.
- **Store mutations** take a snapshot (`s.st.clone()`) and finish with
  `s.commit(snap)`, so a failed save leaves memory as it was.
- **The web UI has no JavaScript.** The CSP forbids scripts. Don't add
  inline scripts, event handlers or third-party assets; use plain forms.
- **Every state-changing form** checks the CSRF token and goes through the
  admin middleware.
- **Masking in `keydrop run`** must keep covering the plain, base64 and
  URL-encoded forms. If you touch `internal/mask`, add a test for the case
  you changed.

If a change needs to bend one of these, stop and ask the maintainer first.

## Dependencies

**Zero third-party Go modules.** Standard library only, including for
crypto, TOTP and TLS. `go.mod` should have no `require` block. If something
seems to need a dependency, ask first and explain why the stdlib can't do it.

GitHub Actions are the exception; keep them to well-known actions
(`actions/*`, `docker/*`).

Renovate keeps Go, the base images and the actions current, and cuts patch
releases for the ones that ship; see "Updates and releases" in
[docs/development.md](docs/development.md).

## Layout

| Path | |
|---|---|
| `cmd/keydrop` | Entry point. `main.go` (dispatch, usage text), `serve.go` (server config from env), `agent.go` (CLI commands). |
| `internal/store` | State file, encryption, secrets, namespaces, tokens. |
| `internal/auth` | Password hashing, TOTP, login limiter. |
| `internal/server` | HTTP server: UI (`ui.go`, `web/`), API (`api.go`), pairing (`pair.go`), the agent setup guide (`setup.go`), TLS. |
| `internal/client` | API client used by the CLI (with certificate pinning). |
| `internal/mask` | Streaming output masker. |
| `internal/qr` | QR encoder for the authenticator setup (stdlib only). |
| `internal/audit` | Audit log. |
| `e2e` | End-to-end tests of the built binary (build tag `e2e`). |

## Build and test

```sh
gofmt -l .            # must print nothing
go vet ./...
go test ./...         # CI also runs -race (needs cgo; may not work on Windows)
go test -tags e2e ./e2e/...   # end-to-end, with the real binary (Linux/macOS)
go build ./cmd/keydrop
docker build -t keydrop:dev .
```

The end-to-end suite (`e2e/`, build tag `e2e`, so plain `go test ./...`
skips it) builds `keydrop`, starts `keydrop server` as a subprocess on a
free localhost port with a temporary data directory, drives the admin web
forms over HTTP and runs the CLI as an agent would, with `HOME` in a
temporary directory (your own `~/.config/keydrop` is never read). It takes
a few seconds after the build and needs `sh`, `base64` and `sha256sum`. The
upgrade test also builds the release at the previous data format from git
history (`git worktree`, removed afterwards); in a shallow clone it skips
with a message, so fetch the full history to run it. CI runs the suite as
its own job. When a change touches the server and CLI together (pairing,
`run`, the data format, TLS), add a step there as well as unit tests.

While iterating, run only the package and tests you're changing
(`go test ./internal/store -run TestFlag`). Run the full list above once
before pushing. In CI, `test`, `e2e` and `image` (one Docker build plus the
CLI install check) run in parallel; `dev-image` pushes afterwards from the
build cache. To confirm a change, wait for `test` and `e2e`; the image jobs
only matter when deploying.

Run it locally:

```sh
go run ./cmd/keydrop genkey > master.key
KEYDROP_MASTER_KEY_FILE=master.key KEYDROP_DATA_DIR=./data go run ./cmd/keydrop server
```

The setup code and the certificate pin are printed in the log. `data/`,
`master.key` and `*.token` are gitignored; keep it that way.

Every behaviour change needs a test. `internal/server/server_test.go` has a
`newHarness` helper that runs the full server in-process; prefer it to mocks.

## Conventions

- Go: `gofmt`, stdlib style, short comments that explain *why*.
- Keep the CLI help text in `cmd/keydrop/main.go`, the README and
  `docs/` in sync with behaviour in the same change.
- **The agent setup guide has one source:**
  `internal/server/web/agent-setup.md.tmpl`. The server renders it for
  `/setup.md` and the "Set up an agent" page; the section of
  `docs/agent-setup.md` between the `BEGIN agent setup` / `END agent setup`
  markers is its generic rendering. Edit the template, never that
  section, then run `go test ./internal/server -run TestAgentSetupDoc -update`
  and commit both; `TestAgentSetupDoc` fails while they differ. It's served
  without auth, so it must only ever hold public values (address, pins).
- New config is an env var named `KEYDROP_*`, documented in the configuration
  table in `docs/install.md`, with a safe default.
- Error messages and UI text: plain English, say what to do next.
- **CLI compatibility:** when you change the agent API, decide whether the
  CLI depends on it and raise `APILevel` / `MinCLILevel` in
  `internal/server/compat.go` as its comment says. Raising `MinCLILevel`
  refuses every older CLI, so it needs a reason in the commit message and a
  new entry in `cliLevelCommits` (`e2e/compat_test.go`).
- UI: follow [docs/ui.md](docs/ui.md), and update it when you add a palette
  variable or component.

## Git

- Work on `dev`; `main` is for releases. CI runs on both.
- Commit messages: a short summary line, then the why if it isn't obvious.
  No AI attribution lines (`Co-Authored-By`, "Generated with …").
- Never commit real secrets, master keys, tokens or data directories, even
  in tests. Test fixtures use obviously fake values.
- Don't push tags or create releases unless the maintainer asks: a `v*` tag
  publishes binaries and an image.

## Private-only setup

This repo is private for now. Anything that only works on the maintainer's
own infrastructure (a self-hosted runner, a private registry, internal
hostnames) must not go into general code or docs. Where it's unavoidable
(for example a workflow file), mark each such line or block with a
`PRIVATE:` comment, so `git grep PRIVATE:` lists everything to remove
before the repo goes public.

CI fails if the tree contains any of the maintainer's own addresses,
domains or host names (`scripts/leak-check.sh`; the list is the
`KEYDROP_LEAK_PATTERNS` repository secret, so it isn't in the repo: one
extended regex per line, surrounding whitespace trimmed, blank lines
ignored). It fails closed: a pattern grep can't compile, or a grep/git error, fails the
check (`scripts/leak-check-test.sh` tests that). Without the secret (forks,
local runs) it skips with a warning that nothing was checked. Use
generic examples: `10.0.0.x`, `192.168.1.50`, `secrets.example.com`. Commit
with a GitHub noreply address.

## Supply chain

- Actions are pinned to a full commit SHA with the version as a comment
  (`uses: actions/checkout@<sha> # v7.0.1`); base images in the
  `Dockerfile` by digest, tag kept for readers. To update, resolve the new
  tag (`git ls-remote --tags`, or the registry's manifest digest for the
  multi-arch index) and change SHA and comment together. Never go back to
  a bare tag.
- Workflow permissions are per job, with nothing at the top level
  (`permissions: {}` in `release.yml`). Anything that publishes `needs:` a
  job that ran the tests on the same commit.

### Before going public

In this order; the maintainer does steps 8 to 10:

1. A thorough security review of the whole codebase, with findings fixed.
   The repo and its history were reviewed for leaks on 2026-11-01:
   no real secrets; the only history-only problems (a personal author
   email on some commits, private addresses in an old test) go away with
   step 6. Private addresses alone are acceptable; the email is not.
2. Check the web UI in a real browser, on a phone and a desktop.
3. Make the e2e tests survive the squash: `e2e/e2e_test.go` and
   `e2e/compat_test.go` build old releases by commit hash, and those
   commits won't exist afterwards. Build them from tags or archived
   release binaries instead, or drop them.
4. Merge `dev` into `main`; CI green on `main`.
5. Run the `leak-history` workflow (it only appears once on the default
   branch) and clean up anything it finds.
6. Squash the history into one commit, authored **and committed** with
   the noreply address, and push it to a **new private repository**.
   Don't force-push this one: GitHub keeps force-pushed-away commits
   fetchable by hash, and each old Actions run still shows its commit's
   author email. Then rename this repo (e.g. `keydrop-old`, kept private)
   and give the new one its name, and link the ghcr.io package to it in
   the package settings. A hard gate for every later step:
   `git log --all --format='%ae%n%ce' | sort -u` on a fresh clone of the
   new repo prints only the noreply address.
7. `git grep PRIVATE:` is empty: each such line removed or made generic.
8. Make the repository and its container package public.
9. Tag `v0.1.0`; the release workflow builds the image and CLI binaries.
   Then give the Renovate app access to the new repo. Not before: patch
   releases count up from this tag, and `bump-version.yml` stops without one.
10. Optionally publish the docs site: Actions → docs → Run workflow on
    `main`, then Settings → Pages → the `gh-pages` branch.
