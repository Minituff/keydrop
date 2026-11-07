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

## Updates and releases

keydrop has no third-party Go modules, so its security updates are Go itself
(the standard library ships with it) and the two base images. Renovate
(`.github/renovate.json5`) opens a PR for each; CI runs on it as on any PR,
and Renovate merges it only when the checks are green.

| Update | Merges by itself | Patch release |
|---|---|---|
| Go patch (1.27.3 → 1.27.4) | Yes, after a day | Yes |
| Go minor or major (1.27 → 1.28) | No, the maintainer reviews it | No |
| Runtime image digest (distroless) | Yes, Mondays | Yes |
| Build image digest, same Go | Yes, Mondays | No, nothing that ships changes |
| GitHub Actions minor, patch, digest | Yes, after two days | No |
| GitHub Actions major | No | No |

Renovate marks the commits that change what ships with `[bump version]`.
`bump-version.yml` sees that on `main`, tags the next patch version and starts
`release.yml`, which runs the tests and e2e again before publishing. Feature
releases are tagged by hand (`v1.2.0`) and later patches count up from there.
Anything merged to `main` since the last tag goes out with the next patch, so
tag feature work as soon as it reaches `main`.

The Go version lives in two places, and `scripts/go-version-check.sh` fails CI
while they differ: `toolchain` in `go.mod` (CI reads it) and the `golang` tag in
the `Dockerfile` (what ships). Renovate changes both in one PR. It doesn't
change the `go` line, so raise that by hand with a new Go minor. The distroless
image name carries the Debian release, so moving to a newer Debian is a manual
change too.

## Roadmap

- Passkeys (WebAuthn) for admin login
- An MCP server exposing **metadata only** (`secrets`, `vars`, `history`, `request`). A
  tool that returns values would put them straight into the transcript.
- Optional per-secret allowlists inside a namespace
- Version history beyond one previous value
