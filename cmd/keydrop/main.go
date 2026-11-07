// Command keydrop is both the keydrop server and the agent CLI.
package main

import (
	"fmt"
	"os"
	"strings"

	"github.com/minituff/keydrop/internal/client"
)

// Set at build time with -ldflags "-X main.version=…". The others say
// where the build came from (Settings shows them) and may be empty:
// the full commit hash, its time in RFC 3339 and the repository's URL.
var (
	version    = "dev"
	commit     string
	commitTime string
	repoURL    string
)

// upgrade-data and downgrade-data are left out of the usage on purpose: they
// only matter for data written before the first release (docs/upgrading.md).
const usage = `keydrop — a secret drop for homelab agents.

Agent commands (pair the machine first: "keydrop pair --url URL"):
  run -e REF [-e VAR=REF]... -- CMD     run CMD with secrets/variables in its environment,
                                         secrets masked (-e NAME sets $NAME; VAR=REF renames;
                                         --no-mask turns masking off, and is logged)
  secrets [--new] [--pending]           list secrets this token can see (no values;
                                         --new: changed since this token last read it),
                                         under [namespace: group] headings
  vars [--new]                          list variables (non-secret settings) with values
  info REF                              show one entry's details (a secret's value never)
  history [NAME] [--since 72h] [--quiet]
                                        recent changes to what this token can see: who
                                         did what, when (values never shown; --quiet:
                                         print nothing when nothing changed)
  flag REF ["reason"] [--link URL]      ask the admin to look at a key (the reason
                                         and link are the admin's only)
  status REF ok|expired|revoked|leaked|replaced-by NAME
                                        mark a key's state for everyone; run warns
                                         when it uses one that isn't ok
  note REF "text"                       propose a note on a key; other agents see it
                                         once the admin approves (prints the link)
  request REF [REF...] --desc TEXT [--usage U] [--group NAME]
                                        ask the human for one or more keys (up to 10, one
                                         namespace), filled on one card; prints a link.
                                         --group suggests a group; the human decides
  wait REF [--timeout 30m]              wait until a requested secret has a value
  expiring [--days 14] [--check]        secrets expiring soon (--check: exit 1 if any)
  get NAME                              print a variable (refuses secrets)
  get REF --to-file PATH                write a value to a 0600 file
  get REF --raw                         print a secret (avoid: it ends up in logs)
  put REF [--var] [--desc …]            store a value read from stdin (add or write
                                         tokens; --var: a variable, not a secret,
                                         write tokens only)
  import FILE [--namespace NS] [--vars] [--overwrite] [--dry-run]
                                        upload a KEY=VALUE env file (add or write tokens;
                                         --vars: as variables, write tokens only)
  pair --url URL [--pin sha256:…] [--new]
                                        ask the admin for a token; prints a link to
                                         approve, waits, then saves it (run again
                                         to keep waiting; --new: start a new request)
  login --url URL [--pin sha256:…]      save the server URL and a pasted token
  whoami                                show the token's name, namespaces, permission and
                                         expiry
  renew [--wait] [--timeout 1h]         ask the admin to renew this token before (or up to
                                         30 days after) it expires; --wait waits for the
                                         approval and saves the new token over the token file.
                                         Any command run after the approval does that too
  upgrade [--force]                     replace this CLI with the paired server's build
                                         (checked against its SHA256SUMS; the old binary is
                                         kept as .<version>.bak). Run it when keydrop says
                                         the server is a different build

Server commands:
  server                                run the server (configured by KEYDROP_* env vars)
  genkey                                print a new master key
  healthcheck                           exit 0 if the local server answers (for Docker)
  rotate-tls                            with the server stopped: replace the self-signed
                                         certificate (old files kept as .bak); prints the
                                         new pin, which every agent then needs

REF is namespace/NAME, or just NAME when the token has one namespace. Secret
names are env-var style: CLOUDFLARE_API_TOKEN.
`

func main() {
	if len(os.Args) < 2 {
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
	client.Version = version
	cmd, args := os.Args[1], os.Args[2:]
	var err error
	switch cmd {
	case "server":
		err = cmdServer(args)
	case "genkey":
		err = cmdGenkey(args)
	case "upgrade-data":
		err = cmdUpgradeData(args)
	case "downgrade-data":
		err = cmdDowngradeData(args)
	case "rotate-tls":
		err = cmdRotateTLS(args)
	case "healthcheck":
		err = cmdHealthcheck(args)
	case "run":
		var code int
		code, err = cmdRun(args)
		if err == nil {
			os.Exit(code)
		}
	case "secrets":
		err = cmdList("secret", args)
	case "vars":
		err = cmdList("variable", args)
	case "info":
		err = cmdInfo(args)
	case "history":
		err = cmdHistory(args)
	case "flag":
		err = cmdFlag(args)
	case "status":
		err = cmdStatus(args)
	case "note":
		err = cmdNote(args)
	case "inbox":
		err = cmdInbox(args)
	case "ack":
		err = cmdAck(args)
	case "request":
		err = cmdRequest(args)
	case "wait":
		err = cmdWait(args)
	case "expiring":
		err = cmdExpiring(args)
	case "get":
		err = cmdGet(args)
	case "put":
		err = cmdPut(args)
	case "import":
		err = cmdImport(args)
	case "login":
		err = cmdLogin(args)
	case "pair":
		err = cmdPair(args)
	case "whoami":
		err = cmdWhoami(args)
	case "renew":
		err = cmdRenew(args)
	case "upgrade":
		err = cmdUpgrade(args)
	case "version", "--version", "-v":
		fmt.Println("keydrop", version)
	case "help", "--help", "-h":
		fmt.Print(usage)
	default:
		fmt.Fprintf(os.Stderr, "keydrop: unknown command %q\n\n%s", cmd, usage)
		os.Exit(2)
	}
	if err != nil {
		var ec exitCode
		if asExit(err, &ec) {
			os.Exit(int(ec))
		}
		// Errors can carry server text: print it inert.
		fmt.Fprintln(os.Stderr, "keydrop:", clean(strings.TrimPrefix(err.Error(), "keydrop: "), true))
		os.Exit(1)
	}
}

// exitCode lets a command exit non-zero without printing an error.
type exitCode int

func (e exitCode) Error() string { return fmt.Sprintf("exit %d", int(e)) }

func asExit(err error, out *exitCode) bool {
	if e, ok := err.(exitCode); ok {
		*out = e
		return true
	}
	return false
}
