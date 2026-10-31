// Command keydrop is both the keydrop server and the agent CLI.
package main

import (
	"fmt"
	"os"
	"strings"
)

// Set at build time with -ldflags "-X main.version=…".
var version = "dev"

const usage = `keydrop — a write-only secret drop for homelab agents.

Agent commands (use a token from the admin UI; see "keydrop login"):
  run [--env VAR=ref]... -- CMD [ARGS]   run CMD with secrets injected, output masked
                                         ({{ref}} in ARGS is replaced too)
  list [--new] [--pending]              list secrets this token can see (no values)
  info REF                              show one secret's details (no value)
  inbox                                 secrets that are new since an agent last acked them
  ack REF...                            mark secrets as dealt with
  request REF --desc TEXT [--usage U]   ask the human for a secret; prints a link
  wait REF [--timeout 30m]              wait until a requested secret has a value
  expiring [--days 14] [--check]        secrets expiring soon (--check: exit 1 if any)
  get REF --to-file PATH                write a value to a 0600 file
  get REF --raw                         print a value (avoid: it ends up in logs)
  put REF [--desc …] [--overwrite]      store a value read from stdin (write tokens)
  import FILE [--namespace NS]          upload a KEY=VALUE env file (write tokens)
  login --url URL [--pin sha256:…]      save the server URL and a token
  whoami                                show the token's name and namespaces

Server commands:
  server                                run the server (configured by KEYDROP_* env vars)
  genkey                                print a new master key
  healthcheck                           exit 0 if the local server answers (for Docker)

REF is namespace/name, or just name when the token has one namespace.
`

func main() {
	if len(os.Args) < 2 {
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
	cmd, args := os.Args[1], os.Args[2:]
	var err error
	switch cmd {
	case "server":
		err = cmdServer(args)
	case "genkey":
		err = cmdGenkey(args)
	case "healthcheck":
		err = cmdHealthcheck(args)
	case "run":
		var code int
		code, err = cmdRun(args)
		if err == nil {
			os.Exit(code)
		}
	case "list":
		err = cmdList(args)
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
