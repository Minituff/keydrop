package server

import (
	"net/http"
	"strconv"
)

// CLI compatibility. Server and CLI are one codebase, so a CLI carries the
// APILevel it was built with. Every dev push changes the version, but most
// don't change what the CLI relies on, so the version alone can't say
// whether an older CLI still works; these levels do.
//
//   - Raise APILevel when the agent API changes in a way the CLI depends
//     on: a new endpoint or field a CLI command uses, or a changed one.
//   - Raise MinCLILevel (to the current APILevel) only when CLIs below it
//     would break against this server. The server then refuses them with
//     426 and a message naming `keydrop upgrade`. Add the commit to
//     cliLevelCommits in e2e/compat_test.go, which runs the oldest CLI at
//     MinCLILevel against this server.
//
// Leave both alone for UI-only or server-internal changes.
const (
	APILevel    = 1
	MinCLILevel = 1
)

// Headers: the CLI sends its level; authenticated responses carry the
// server's. A request without one (CLIs before levels existed, curl) counts
// as level 1.
const (
	HdrCLILevel = "X-Keydrop-Cli-Level"
	HdrAPILevel = "X-Keydrop-Api-Level"
	HdrMinCLI   = "X-Keydrop-Min-Cli-Level"
)

// cliLevel is the level a request declares (1 when it says nothing).
func cliLevel(r *http.Request) int {
	n, err := strconv.Atoi(r.Header.Get(HdrCLILevel))
	if err != nil || n < 0 {
		return 1
	}
	return n
}

// tooOldCLI is the 426 message. CLIs before levels existed have no
// upgrade command, so it names the installer as well.
const tooOldCLI = "this keydrop CLI is too old for this server: run `keydrop upgrade` (or, if this CLI has no upgrade command, reinstall it from the server's /install.sh)"
