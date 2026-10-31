package main

import (
	"bufio"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/url"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
	"time"

	"github.com/minituff/keydrop/internal/client"
	"github.com/minituff/keydrop/internal/mask"
	"github.com/minituff/keydrop/internal/store"
)

// parse parses flags that may come before or after positional arguments
// ("keydrop request NAME --desc …") and returns the positionals.
func parse(fs *flag.FlagSet, args []string) []string {
	var pos []string
	for {
		fs.Parse(args)
		args = fs.Args()
		if len(args) == 0 {
			return pos
		}
		if args[0] == "--" {
			return append(pos, args[1:]...)
		}
		pos = append(pos, args[0])
		args = args[1:]
	}
}

func newClient() (*client.Client, error) { return client.FromEnv() }

func ago(t time.Time) string {
	d := time.Since(t)
	switch {
	case d < time.Minute:
		return "just now"
	case d < time.Hour:
		return fmt.Sprintf("%dm ago", int(d.Minutes()))
	case d < 48*time.Hour:
		return fmt.Sprintf("%dh ago", int(d.Hours()))
	default:
		return fmt.Sprintf("%dd ago", int(d.Hours()/24))
	}
}

func printSecret(w io.Writer, s client.Secret, long bool) {
	var tags []string
	switch {
	case s.Pending:
		tags = append(tags, "waiting for a value")
	case !s.HasValue:
		tags = append(tags, "no value")
	}
	if s.New {
		tags = append(tags, "new")
	}
	if s.Expires != nil {
		if time.Now().After(*s.Expires) {
			tags = append(tags, "EXPIRED "+s.Expires.Format("2006-01-02"))
		} else {
			tags = append(tags, "expires "+s.Expires.Format("2006-01-02"))
		}
	}
	line := s.Ref
	if len(tags) > 0 {
		line += "  [" + strings.Join(tags, ", ") + "]"
	}
	fmt.Fprintln(w, line)
	if s.Description != "" {
		for _, l := range strings.Split(s.Description, "\n") {
			fmt.Fprintln(w, "    "+l)
		}
	}
	if s.Usage != "" {
		fmt.Fprintln(w, "    usage: "+s.Usage)
	}
	if long {
		fmt.Fprintf(w, "    updated %s", ago(s.UpdatedAt))
		if s.LastReadAt != nil {
			fmt.Fprintf(w, ", last read %s by %s", ago(*s.LastReadAt), s.LastReadBy)
		}
		if s.RequestedBy != "" {
			fmt.Fprintf(w, ", requested by %s", s.RequestedBy)
		}
		fmt.Fprintln(w)
	}
}

func cmdWhoami(args []string) error {
	c, err := newClient()
	if err != nil {
		return err
	}
	w, err := c.Whoami()
	if err != nil {
		return err
	}
	fmt.Printf("%s @ %s\nnamespaces: %s\nwrite: %v\n", w.Name, c.URL, strings.Join(w.Namespaces, ", "), w.Write)
	return nil
}

func cmdList(args []string) error {
	fs := flag.NewFlagSet("list", flag.ExitOnError)
	onlyNew := fs.Bool("new", false, "only new secrets")
	pending := fs.Bool("pending", false, "only requested secrets still waiting for a value")
	ns := fs.String("namespace", "", "only this namespace")
	parse(fs, args)
	c, err := newClient()
	if err != nil {
		return err
	}
	q := url.Values{}
	if *onlyNew {
		q.Set("new", "1")
	}
	if *pending {
		q.Set("pending", "1")
	}
	if *ns != "" {
		q.Set("namespace", *ns)
	}
	list, err := c.List(q)
	if err != nil {
		return err
	}
	if len(list) == 0 {
		fmt.Println("(none)")
	}
	for _, s := range list {
		printSecret(os.Stdout, s, false)
	}
	return nil
}

func cmdInfo(args []string) error {
	fs := flag.NewFlagSet("info", flag.ExitOnError)
	pos := parse(fs, args)
	if len(pos) != 1 {
		return errors.New("usage: keydrop info REF")
	}
	c, err := newClient()
	if err != nil {
		return err
	}
	s, err := c.Get(pos[0])
	if err != nil {
		return err
	}
	printSecret(os.Stdout, *s, true)
	return nil
}

// cmdInbox is meant for an agent's session-start hook: it says what's new
// and what's still waiting, with the descriptions that say what to do.
func cmdInbox(args []string) error {
	fs := flag.NewFlagSet("inbox", flag.ExitOnError)
	quiet := fs.Bool("quiet", false, "print nothing when the inbox is empty")
	parse(fs, args)
	c, err := newClient()
	if err != nil {
		return err
	}
	all, err := c.List(nil)
	if err != nil {
		return err
	}
	var fresh, waiting []client.Secret
	for _, s := range all {
		switch {
		case s.Pending:
			waiting = append(waiting, s)
		case s.New:
			fresh = append(fresh, s)
		}
	}
	if len(fresh) == 0 && len(waiting) == 0 {
		if !*quiet {
			fmt.Println("keydrop inbox: nothing new.")
		}
		return nil
	}
	if len(fresh) > 0 {
		fmt.Printf("keydrop: %d new secret(s). Read each description for what to do, use them with `keydrop run`, then `keydrop ack REF`.\n", len(fresh))
		for _, s := range fresh {
			printSecret(os.Stdout, s, true)
		}
	}
	if len(waiting) > 0 {
		fmt.Printf("keydrop: %d request(s) still waiting for the human:\n", len(waiting))
		for _, s := range waiting {
			printSecret(os.Stdout, s, true)
		}
	}
	return nil
}

func cmdAck(args []string) error {
	fs := flag.NewFlagSet("ack", flag.ExitOnError)
	pos := parse(fs, args)
	if len(pos) == 0 {
		return errors.New("usage: keydrop ack REF...")
	}
	c, err := newClient()
	if err != nil {
		return err
	}
	for _, ref := range pos {
		if err := c.Ack(ref); err != nil {
			return err
		}
		fmt.Println("acked", ref)
	}
	return nil
}

func cmdRequest(args []string) error {
	fs := flag.NewFlagSet("request", flag.ExitOnError)
	desc := fs.String("desc", "", "what it's for and how to create it (shown to the human)")
	use := fs.String("usage", "", "how it'll be used, e.g. 'Authorization: Bearer {}'")
	pos := parse(fs, args)
	if len(pos) != 1 || *desc == "" {
		return errors.New("usage: keydrop request REF --desc \"what it's for, which scopes, how long it should last\"")
	}
	c, err := newClient()
	if err != nil {
		return err
	}
	link, err := c.Request(pos[0], *desc, *use)
	if err != nil {
		return err
	}
	fmt.Println("Requested. The human can fill it in here:")
	fmt.Println(link)
	fmt.Println("Then: keydrop wait " + pos[0])
	return nil
}

func cmdWait(args []string) error {
	fs := flag.NewFlagSet("wait", flag.ExitOnError)
	timeout := fs.Duration("timeout", 30*time.Minute, "give up after this long")
	every := fs.Duration("interval", 5*time.Second, "how often to check")
	pos := parse(fs, args)
	if len(pos) != 1 {
		return errors.New("usage: keydrop wait REF [--timeout 30m]")
	}
	c, err := newClient()
	if err != nil {
		return err
	}
	deadline := time.Now().Add(*timeout)
	said := false
	for {
		s, err := c.Get(pos[0])
		if err != nil && !client.IsNotFound(err) {
			return err
		}
		if err == nil && s.HasValue && !s.Pending {
			fmt.Println(s.Ref, "is ready.")
			return nil
		}
		if time.Now().After(deadline) {
			fmt.Fprintln(os.Stderr, "keydrop: timed out waiting for", pos[0])
			return exitCode(2)
		}
		if !said {
			fmt.Fprintln(os.Stderr, "waiting for", pos[0], "…")
			said = true
		}
		time.Sleep(*every)
	}
}

func cmdExpiring(args []string) error {
	fs := flag.NewFlagSet("expiring", flag.ExitOnError)
	days := fs.Int("days", 14, "look this many days ahead")
	check := fs.Bool("check", false, "exit 1 if anything is expiring (for health checks)")
	parse(fs, args)
	c, err := newClient()
	if err != nil {
		return err
	}
	list, err := c.Expiring(*days)
	if err != nil {
		return err
	}
	for _, s := range list {
		printSecret(os.Stdout, s, false)
	}
	if *check && len(list) > 0 {
		return exitCode(1)
	}
	return nil
}

// ---- run ----

type multiFlag []string

func (m *multiFlag) String() string     { return strings.Join(*m, ",") }
func (m *multiFlag) Set(v string) error { *m = append(*m, v); return nil }

var envNameRE = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

type binding struct{ envVar, ref string }

// parseEnvFlag reads one -e value: NAME or ns/NAME injects the secret under
// its own name, VAR=REF under another.
func parseEnvFlag(e string) (binding, error) {
	if v, ref, ok := strings.Cut(e, "="); ok {
		if !envNameRE.MatchString(v) || ref == "" {
			return binding{}, fmt.Errorf("-e %q: want NAME or VAR=NAME", e)
		}
		return binding{v, ref}, nil
	}
	name := e
	if i := strings.LastIndex(e, "/"); i >= 0 {
		name = e[i+1:]
	}
	if !envNameRE.MatchString(name) {
		return binding{}, fmt.Errorf("-e %q: want NAME or VAR=NAME", e)
	}
	return binding{name, e}, nil
}

func cmdRun(args []string) (int, error) {
	fs := flag.NewFlagSet("run", flag.ExitOnError)
	var envs multiFlag
	fs.Var(&envs, "e", "NAME, ns/NAME or VAR=NAME: put a secret in the command's environment (repeatable)")
	fs.Var(&envs, "env", "same as -e")
	noMask := fs.Bool("no-mask", false, "don't mask secret values in the command's output")
	fs.Parse(args)
	argv := fs.Args()
	if len(argv) == 0 || len(envs) == 0 {
		return 0, errors.New("usage: keydrop run -e NAME [-e VAR=NAME]... -- CMD [ARGS]")
	}

	var binds []binding
	refs := map[string]bool{}
	seen := map[string]bool{}
	for _, e := range envs {
		b, err := parseEnvFlag(e)
		if err != nil {
			return 0, err
		}
		if seen[b.envVar] {
			return 0, fmt.Errorf("-e: %s is set twice", b.envVar)
		}
		seen[b.envVar] = true
		binds = append(binds, b)
		refs[b.ref] = true
	}

	c, err := newClient()
	if err != nil {
		return 0, err
	}
	purpose := "run " + filepath.Base(argv[0])
	values := map[string]string{}
	var m mask.Masker
	for ref := range refs {
		v, err := c.Reveal(ref, purpose)
		if err != nil {
			return 0, fmt.Errorf("%s: %w", ref, err)
		}
		values[ref] = v
		if !m.Add(ref, []byte(v)) && !*noMask {
			fmt.Fprintf(os.Stderr, "keydrop: warning: %s is shorter than %d characters and won't be masked\n", ref, mask.MinLength)
		}
	}

	var childEnv []string
	for _, kv := range os.Environ() {
		if !strings.HasPrefix(kv, "KEYDROP_TOKEN=") { // the child never needs the agent's token
			childEnv = append(childEnv, kv)
		}
	}
	for _, b := range binds {
		childEnv = append(childEnv, b.envVar+"="+values[b.ref])
	}

	cmd := exec.Command(argv[0], argv[1:]...)
	cmd.Env = childEnv
	cmd.Stdin = os.Stdin
	var flushers []*mask.Writer
	if *noMask {
		cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
	} else {
		ow, ew := m.Writer(os.Stdout), m.Writer(os.Stderr)
		cmd.Stdout, cmd.Stderr = ow, ew
		flushers = append(flushers, ow, ew)
	}
	if err := cmd.Start(); err != nil {
		return 0, err
	}
	sigs := make(chan os.Signal, 4)
	signal.Notify(sigs, os.Interrupt, syscall.SIGTERM, syscall.SIGHUP)
	go func() {
		for s := range sigs {
			cmd.Process.Signal(s)
		}
	}()
	err = cmd.Wait()
	signal.Stop(sigs)
	for _, f := range flushers {
		f.Flush()
	}
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		if ws, ok := ee.Sys().(syscall.WaitStatus); ok && ws.Signaled() {
			return 128 + int(ws.Signal()), nil
		}
		return ee.ExitCode(), nil
	}
	return 0, err
}

// ---- get / put / import ----

func cmdGet(args []string) error {
	fs := flag.NewFlagSet("get", flag.ExitOnError)
	toFile := fs.String("to-file", "", "write the value to this file (mode 600)")
	force := fs.Bool("force", false, "overwrite --to-file if it exists")
	raw := fs.Bool("raw", false, "print the value to stdout")
	pos := parse(fs, args)
	if len(pos) != 1 || (*toFile == "") == !*raw {
		return errors.New("usage: keydrop get REF --to-file PATH   (or --raw to print it, which leaks it into logs)")
	}
	c, err := newClient()
	if err != nil {
		return err
	}
	purpose := "get --raw"
	if *toFile != "" {
		purpose = "get --to-file"
	}
	v, err := c.Reveal(pos[0], purpose)
	if err != nil {
		return err
	}
	if *raw {
		fmt.Fprintln(os.Stderr, "keydrop: printing a secret; it's now in this terminal's output")
		fmt.Print(v)
		return nil
	}
	flags := os.O_WRONLY | os.O_CREATE | os.O_EXCL
	if *force {
		flags = os.O_WRONLY | os.O_CREATE | os.O_TRUNC
	}
	f, err := os.OpenFile(*toFile, flags, 0o600)
	if err != nil {
		return err
	}
	if _, err := f.WriteString(v); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	fmt.Println("wrote", pos[0], "to", *toFile)
	return nil
}

func isTerminal(f *os.File) bool {
	fi, err := f.Stat()
	return err == nil && fi.Mode()&os.ModeCharDevice != 0
}

// readSecretLine reads one line from stdin, without echo on a terminal.
func readSecretLine(prompt string) (string, error) {
	if isTerminal(os.Stdin) {
		fmt.Fprint(os.Stderr, prompt)
		stty := func(arg string) {
			c := exec.Command("stty", arg)
			c.Stdin = os.Stdin
			c.Run()
		}
		stty("-echo")
		defer func() { stty("echo"); fmt.Fprintln(os.Stderr) }()
	}
	line, err := bufio.NewReader(os.Stdin).ReadString('\n')
	if err != nil && !(errors.Is(err, io.EOF) && line != "") {
		return "", err
	}
	return strings.TrimRight(line, "\r\n"), nil
}

func cmdPut(args []string) error {
	fs := flag.NewFlagSet("put", flag.ExitOnError)
	desc := fs.String("desc", "", "description")
	use := fs.String("usage", "", "usage hint")
	expires := fs.String("expires", "", "expiry date, e.g. 2027-01-23")
	overwrite := fs.Bool("overwrite", false, "replace an existing value")
	keepWS := fs.Bool("keep-ws", false, "keep leading/trailing whitespace")
	pos := parse(fs, args)
	if len(pos) != 1 {
		return errors.New("usage: keydrop put REF [--desc TEXT] < value   (the value comes from stdin, never the command line)")
	}
	var v string
	if isTerminal(os.Stdin) {
		line, err := readSecretLine("Value: ")
		if err != nil {
			return err
		}
		v = line
	} else {
		b, err := io.ReadAll(io.LimitReader(os.Stdin, 64<<10))
		if err != nil {
			return err
		}
		v = string(b)
	}
	if !*keepWS {
		v = strings.TrimSpace(v)
	}
	if v == "" {
		return errors.New("empty value")
	}
	o := client.PutOptions{Overwrite: *overwrite}
	if *desc != "" {
		o.Description = desc
	}
	if *use != "" {
		o.Usage = use
	}
	if *expires != "" {
		o.Expires = expires
	}
	c, err := newClient()
	if err != nil {
		return err
	}
	if err := c.Put(pos[0], v, o); err != nil {
		return err
	}
	fmt.Println("stored", pos[0])
	return nil
}

type envEntry struct{ key, value, comment string }

// parseEnvFile reads KEY=VALUE lines. Comment lines directly above a key
// become its description.
func parseEnvFile(r io.Reader) ([]envEntry, error) {
	var out []envEntry
	var comment []string
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 64<<10), 1<<20)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		switch {
		case line == "":
			comment = nil
			continue
		case strings.HasPrefix(line, "#"):
			comment = append(comment, strings.TrimSpace(strings.TrimPrefix(line, "#")))
			continue
		}
		line = strings.TrimPrefix(line, "export ")
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			comment = nil
			continue
		}
		k, v = strings.TrimSpace(k), strings.TrimSpace(v)
		if len(v) >= 2 && (v[0] == '"' || v[0] == '\'') && v[len(v)-1] == v[0] {
			v = v[1 : len(v)-1]
		}
		out = append(out, envEntry{k, v, strings.Join(comment, "\n")})
		comment = nil
	}
	return out, sc.Err()
}

func cmdImport(args []string) error {
	fs := flag.NewFlagSet("import", flag.ExitOnError)
	ns := fs.String("namespace", "", "namespace to import into (default: the token's only namespace)")
	overwrite := fs.Bool("overwrite", false, "replace secrets that already have a value")
	dry := fs.Bool("dry-run", false, "show what would be imported (names only)")
	pos := parse(fs, args)
	if len(pos) != 1 {
		return errors.New("usage: keydrop import FILE [--namespace NS] [--dry-run]")
	}
	f, err := os.Open(pos[0])
	if err != nil {
		return err
	}
	entries, err := parseEnvFile(f)
	f.Close()
	if err != nil {
		return err
	}
	c, err := newClient()
	if err != nil {
		return err
	}
	if *ns == "" {
		w, err := c.Whoami()
		if err != nil {
			return err
		}
		if len(w.Namespaces) != 1 {
			return errors.New("this token has several namespaces; pass --namespace")
		}
		*ns = w.Namespaces[0]
	}
	var done, skipped int
	for _, e := range entries {
		ref := *ns + "/" + e.key
		switch {
		case !store.ValidSecretName(e.key):
			fmt.Printf("skip %s: secret names are capital letters, digits and '_'\n", e.key)
			skipped++
			continue
		case e.value == "":
			fmt.Printf("skip %s: empty\n", e.key)
			skipped++
			continue
		}
		if *dry {
			fmt.Printf("would import %s\n", ref)
			continue
		}
		desc := e.comment
		if desc == "" {
			desc = "Imported from " + filepath.Base(pos[0])
		}
		err := c.Put(ref, e.value, client.PutOptions{Description: &desc, Overwrite: *overwrite})
		var ae *client.APIError
		if errors.As(err, &ae) && ae.Status == 409 {
			fmt.Printf("skip %s: already exists (use --overwrite)\n", ref)
			skipped++
			continue
		}
		if err != nil {
			return fmt.Errorf("%s: %w", e.key, err)
		}
		fmt.Printf("imported %s\n", ref)
		done++
	}
	if !*dry {
		fmt.Printf("%d imported, %d skipped. Values were not printed.\n", done, skipped)
	}
	return nil
}

// ---- login ----

func cmdLogin(args []string) error {
	fs := flag.NewFlagSet("login", flag.ExitOnError)
	u := fs.String("url", "", "server URL, e.g. https://10.0.0.5:8443")
	pin := fs.String("pin", "", "certificate pin for a self-signed server (sha256:…, printed in the server log)")
	parse(fs, args)
	if *u == "" {
		return errors.New("usage: keydrop login --url URL [--pin sha256:…], then paste the token")
	}
	tok, err := readSecretLine("Token: ")
	if err != nil {
		return err
	}
	tok = strings.TrimSpace(tok)
	c := client.New(*u, tok, *pin)
	w, err := c.Whoami()
	if err != nil {
		return err
	}
	dir := client.ConfigDir()
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	files := map[string]string{"url": *u, "token": tok}
	if *pin != "" {
		files["pin"] = *pin
	} else {
		os.Remove(filepath.Join(dir, "pin"))
	}
	for name, v := range files {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(v+"\n"), 0o600); err != nil {
			return err
		}
	}
	fmt.Printf("Logged in as %s (namespaces: %s). Saved to %s\n", w.Name, strings.Join(w.Namespaces, ", "), dir)
	return nil
}
