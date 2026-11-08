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

Pushes to `dev` and `main` only run the tests. To publish, go to
**Actions → release → Run workflow**, pick a branch and type a tag:

| Tag | Publishes |
|---|---|
| `v1.2.3` from `main` | GitHub release with CLI binaries and `SHA256SUMS`, multi-arch image tagged `1.2.3`, `1.2` and `latest` |
| `v1.2.3` from another branch, or `v1.2.3-rc.1` | The same as a pre-release, with only the full version tag on the image (`1.2.3-rc.1`) |
| Any other name, like `dev` | Only a multi-arch image with that tag; its version is `dev-<sha>` |

**To write the release notes yourself,** go to **Releases → Draft a new
release**, type the new tag, write the notes, and press **Save draft**, not
Publish. Then run the workflow with the same tag. It attaches the binaries and
publishes the draft. Releases are immutable once published, so one published
straight from that page can never get its binaries: use a new tag instead.

Pushing a `v*` tag does the same as running the workflow. A version tag can't move to another
commit, and `latest` can't be typed by hand. Other tags such as `dev` do
move, so pin them by digest. Everything is built on GitHub-hosted runners,
with an SBOM and provenance on the image and a signed build attestation on
both the image and the binaries. Check that `release.yml` signed it, built
from the release's tag:

```sh
gh attestation verify keydrop-linux-amd64 --repo Minituff/keydrop \
  --signer-workflow Minituff/keydrop/.github/workflows/release.yml \
  --source-ref refs/tags/v1.2.3
gh attestation verify oci://ghcr.io/minituff/keydrop:1.2.3 --repo Minituff/keydrop \
  --signer-workflow Minituff/keydrop/.github/workflows/release.yml \
  --source-ref refs/tags/v1.2.3
```

A release started from **Run workflow** is built from the branch you picked,
not the tag. For one of those, `--source-ref refs/heads/main` only shows it was
built from `main`, not from the tag's commit, so also pin the commit:
`--source-ref refs/heads/main --source-digest "$(git rev-parse 'v1.2.3^{commit}')"`.
Pushed tags and Renovate's patch releases are built from the tag.

Every image includes the CLI for all six platforms (about 24 MB compressed);
CI installs it from a running image with `install.sh` and checks the version.
Nothing is published unless the tests passed on that commit, and no publishing
job reads the Actions cache. Workflow actions are pinned to commit SHAs and
base images to digests. Images built by CI link the version in Settings to
its commit (build args `COMMIT`, `COMMIT_TIME`, `REPO_URL`).

CI also uploads unit test coverage to Codecov. The e2e suite isn't counted,
and an outage at Codecov doesn't fail CI.

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
`release.yml`, which runs the tests and e2e again before publishing. This is
the only release that starts by itself. Feature releases are started by hand
(`v1.2.0`) and later patches count up from there, so `bump-version.yml` stops
with an error until the first version tag exists.
Anything merged to `main` since the last tag goes out with the next patch, so
tag feature work as soon as it reaches `main`.

### When an unattended run fails

`autofix.yml` hands a failure nobody is watching to a Claude Code routine:
a check on a Renovate PR, a push Renovate merged to `main`, or a release
`bump-version.yml` started. It sends only fixed text: the run's link, workflow,
branch and commit, and for a Renovate PR its number. For a Renovate PR the
routine may open a fix PR into `dev`; for the others it only opens an issue
with its diagnosis.

Before sending, the workflow checks the PR is Renovate's, still at the failed
commit and aimed at `main`, and skips a branch that already has an open
`autofix` issue or PR from the owner, or a hand-off earlier that day. It
hands off at most about five failures a day (a soft cap: failures on two
branches at the same moment can both get through), and only a run's first
attempt.

**What's enforced and what's only asked.** GitHub's proxy in Claude's cloud
refuses to push tags or delete branches, and `main` takes changes only
through a pull request. That's all. Pushing only to `claude/*` branches is
Claude's default, not a limit: the proxy lets a push update any branch, and
`dev` has no rule against a direct push. Everything else is only its
instructions: push only to its own branch, open PRs into `dev` and issues,
and never merge, approve, start or re-run workflows, release, or change
settings. The routine acts on GitHub with the repository owner's rights, and
`main` needs no approving review, so a run that ignored its instructions
could do what the owner can, merging and releasing included, until it gets
an identity of its own. The only changes meant to merge and release by
themselves are Renovate's, in the table above, and only with every check
green.

Set the repository variable `AUTOFIX` to `off` to pause
it. The routine's URL and token are the `CLAUDE_AUTOFIX_URL` and `CLAUDE_AUTOFIX_TOKEN`
secrets in the `autofix` environment, which only `main` may use, so a
workflow pushed on another branch can't read them; without them it does
nothing. Its prompt and setup are in
`.github/autofix/`, with the sha256 of the version recorded as live:
`scripts/autofix-check.sh` fails CI while a file and its recorded sum differ,
as a reminder to paste the new version into the routine. It can't see the
routine itself, so updating the sum without pasting also passes.

The Go version lives in two places, and `scripts/go-version-check.sh` fails CI
while they differ: `toolchain` in `go.mod` (CI reads it) and the `golang` tag in
the `Dockerfile` (what ships). Renovate changes both in one PR. It doesn't
change the `go` line, so raise that by hand with a new Go minor. The distroless
image name carries the Debian release, so moving to a newer Debian is a manual
change too.

## Roadmap

- Ship the example hook scripts from [agent-setup.md](agent-setup.md) (the
  session-start history, the `--raw` guard) as files rather than docs
- Passkeys (WebAuthn) for admin login
- Trusted proxy-header auth (Authelia, Authentik), left out so far because a
  misconfigured proxy would bypass the login
- An MCP server exposing **metadata only** (`secrets`, `vars`, `history`, `request`). A
  tool that returns values would put them straight into the transcript.
- `--stdin-to CMD` (for example `docker login --password-stdin`)
- Optional per-secret allowlists inside a namespace
- Version history beyond one previous value
- An OpenAPI description of the agent API
