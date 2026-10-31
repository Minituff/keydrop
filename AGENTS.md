# AGENTS.md — working on keydrop

Instructions for AI coding agents (Claude Code, Codex, others) and humans
working on this repo. Read [docs/design_doc.md](docs/design_doc.md) for the
design and the reasons behind it before changing behaviour.

keydrop holds other people's API keys. Treat every change as
security-sensitive: a small convenience that weakens one of the rules below
isn't worth it.

## Security invariants — don't break these

- **Values are only shown on purpose, and every view is logged.** In the
  web UI a value appears only after the admin presses "Show value" (a POST
  with the CSRF token), never in a list, a URL or a redirect. Agents get
  values only from `POST /api/v1/secrets/{ns}/{name}/reveal` with a token.
  Both are audit-logged, and those are the only two ways a value leaves the
  server.
- **Never log, print or return a value or token** anywhere else: not in
  logs, errors, audit entries, webhooks, templates or test output. Errors
  name the secret (`ns/name`), never its contents.
- **Namespace isolation.** A secret in a namespace the token isn't granted
  returns **404**, identical to a missing secret, so names don't leak. Every
  new API endpoint must go through the same grant check.
- **Agents never get admin rights.** Tokens can't create tokens, change
  grants, or reach the UI.
- **Encryption at rest:** AES-256-GCM per value, with the namespace, name and
  field bound as additional data. The master key is never written to the
  data directory.
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

## Layout

| Path | |
|---|---|
| `cmd/keydrop` | Entry point. `main.go` (dispatch, usage text), `serve.go` (server config from env), `agent.go` (CLI commands). |
| `internal/store` | State file, encryption, secrets, namespaces, tokens. |
| `internal/auth` | Password hashing, TOTP, login limiter. |
| `internal/server` | HTTP server: UI (`ui.go`, `web/`), API (`api.go`), TLS. |
| `internal/client` | API client used by the CLI (with certificate pinning). |
| `internal/mask` | Streaming output masker. |
| `internal/qr` | QR encoder for the authenticator setup (stdlib only). |
| `internal/audit`, `internal/notify` | Audit log, webhooks. |

## Build and test

```sh
gofmt -l .            # must print nothing
go vet ./...
go test ./...         # CI also runs -race (needs cgo; may not work on Windows)
go build ./cmd/keydrop
docker build -t keydrop:dev .
```

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
- New config is an env var named `KEYDROP_*`, documented in the README's
  configuration table, with a safe default.
- Error messages and UI text: plain English, say what to do next.

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
