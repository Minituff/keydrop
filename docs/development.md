# Development

Working on keydrop itself. Read [AGENTS.md](https://github.com/Minituff/keydrop/blob/main/AGENTS.md) first (it's for people too), then the [design doc](design_doc.md) and, for the web UI, [UI styling](ui.md).

## Building

```sh
go test ./...
go test -tags e2e ./e2e/...                   # end-to-end: the real binary as server and CLI
go build ./cmd/keydrop                        # this platform
GOOS=linux GOARCH=amd64 go build ./cmd/keydrop  # cross-compile (from Windows too)
docker build -t keydrop .
```

Tags `v*` publish CLI binaries with `SHA256SUMS` to the GitHub release, and a
multi-arch image (with SBOM and provenance) to GHCR, from GitHub-hosted
runners. Pushes to `dev` publish an amd64 image tagged `dev` and
`dev-<sha>` (its version is `dev-<sha>` too) once the tests pass; pin it by
digest, not by the moving tag. Every image includes the CLI for all six
platforms (about 24 MB compressed); CI installs it from a running image
with `install.sh` and checks the version before anything is published.
Nothing is published unless the tests passed on that commit. Workflow
actions are pinned to commit SHAs and base images to digests.

## Roadmap

- Passkeys (WebAuthn) for admin login
- An MCP server exposing **metadata only** (`secrets`, `vars`, `history`, `request`). A
  tool that returns values would put them straight into the transcript.
- Optional per-secret allowlists inside a namespace
- Version history beyond one previous value
