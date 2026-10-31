// Command keydrop is both the keydrop server and the agent CLI.
package main

import (
	"fmt"
	"os"
	"strings"

	"github.com/minituff/keydrop/internal/client"
)

// Set at build time with -ldflags "-X main.version=…".
var version = "dev"

const usage = `keydrop — a secret drop for homelab agents.

Agent commands (pair the machine first: "keydrop pair --url URL"):
  run -e REF [-e VAR=REF]... -- CMD     run CMD with secrets/variables in its environment,
                                         secrets masked (-e NAME sets $NAME; VAR=REF renames)
  secrets [--new] [--pending]           list secrets this token can see (no values)
  vars [--new]                          list variables (non-secret settings) with values
  info REF                              show one entry's details (a secret's value never)
  inbox                                 secrets that are new since an agent last acked them
  ack REF...                            mark secrets as dealt with
  request REF --desc TEXT [--usage U]   ask the human for a secret; prints a link
  wait REF [--timeout 30m]              wait until a requested secret has a value
  expiring [--days 14] [--check]        secrets expiring soon (--check: exit 1 if any)
  get NAME                              print a variable (refuses secrets)
  get REF --to-file PATH                write a value to a 0600 file
  get REF --raw                         print a secret (avoid: it ends up in logs)
  put REF [--var] [--desc …]            store a value read from stdin (write tokens;
                                         --var: a variable, not a secret)
  import FILE [--namespace NS] [--vars] upload a KEY=VALUE env file (write tokens)
  pair --url URL [--pin sha256:…]       ask the admin for a token; prints a link to
                                         approve, waits, then saves it (run again
                                         to keep waiting)
  login --url URL [--pin sha256:…]      save the server URL and a pasted token
  whoami                                show the token's name and namespaces

Server commands:
  server                                run the server (configured by KEYDROP_* env vars)
  genkey                                print a new master key
  healthcheck                           exit 0 if the local server answers (for Docker)
  downgrade-data                        with the server stopped: rewrite the data directory
                                         so a release without the sealed TLS key and
                                         integrity check can read it again

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
	case "downgrade-data":
		err = cmdDowngradeData(args)
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
		fmt.Fprintln(os.Stderr, "keydrop:", strings.TrimPrefix(err.Error(), "keydrop: "))
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
