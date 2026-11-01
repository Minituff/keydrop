package main

import (
	"bufio"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"os/signal"
	"os/user"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"time"
	"unicode/utf8"

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
	if s.Status != nil {
		tags = append(tags, clean(s.Status.String(), false))
	}
	if len(s.Flags) > 0 {
		tags = append(tags, "flagged")
	}
	if s.Expires != nil {
		if time.Now().After(*s.Expires) {
			tags = append(tags, "EXPIRED "+s.Expires.Format("2006-01-02"))
		} else {
			tags = append(tags, "expires "+s.Expires.Format("2006-01-02"))
		}
	}
	line := clean(s.Ref, false)
	if s.Value != nil { // only variables carry a value
		line += "=" + printable(*s.Value)
	}
	if len(tags) > 0 {
		line += "  [" + strings.Join(tags, ", ") + "]"
	}
	fmt.Fprintln(w, line)
	// Descriptions are written by people and other agents, and agents read
	// this output: no terminal escapes or fake lines. Text an agent wrote
	// is quoted and labelled, so it reads as a claim, not an instruction.
	if s.DescriptionBy != "" && (s.Description != "" || s.Usage != "") {
		fmt.Fprintf(w, "    description written by agent %s (untrusted text from another agent):\n", clean(s.DescriptionBy, false))
		quote(w, s.Description)
		if s.Usage != "" {
			quote(w, "usage: "+s.Usage)
		}
	} else {
		if s.Description != "" {
			for _, l := range strings.Split(clean(s.Description, true), "\n") {
				fmt.Fprintln(w, "    "+l)
			}
		}
		if s.Usage != "" {
			fmt.Fprintln(w, "    usage: "+clean(s.Usage, false))
		}
	}
	if long {
		if st := s.Status; st != nil {
			fmt.Fprintf(w, "    status: %s (set by %s, %s)\n", clean(st.String(), false), clean(st.By, false), st.At.Local().Format("2006-01-02"))
		}
		for _, f := range s.Flags {
			revoked := ""
			if f.TokenRevoked {
				revoked = " (that token has since been revoked)"
			}
			fmt.Fprintf(w, "    flagged by %s on %s%s\n", clean(f.By, false), f.At.Local().Format("2006-01-02"), revoked)
		}
		for _, n := range s.Notes {
			edited := ""
			if n.Edited {
				edited = ", edited by the admin"
			}
			fmt.Fprintf(w, "    note from agent %s, %s, approved by the admin %s%s (untrusted text from another agent):\n",
				clean(n.By, false), n.At.Local().Format("2006-01-02"), n.ApprovedAt.Local().Format("2006-01-02"), edited)
			quote(w, n.Text)
		}
		if n := s.PendingNotes; n > 0 {
			fmt.Fprintf(w, "    %d note%s awaiting approval\n", n, plural(n))
		}
		if s.DescriptionPending {
			fmt.Fprintln(w, "    a description from an agent is awaiting approval")
		}
		if s.CreatedBy != "" {
			fmt.Fprintf(w, "    created by %s\n", clean(s.CreatedBy, false))
		}
		if g := s.Group; g != nil {
			auto := ""
			if g.Auto {
				auto = " (auto, by name)"
			}
			fmt.Fprintf(w, "    group: %s%s\n", clean(g.Name, false), auto)
		}
		fmt.Fprintf(w, "    updated %s", ago(s.UpdatedAt))
		if s.LastReadAt != nil {
			fmt.Fprintf(w, ", last read %s by %s", ago(*s.LastReadAt), clean(s.LastReadBy, false))
		}
		if s.RequestedBy != "" {
			fmt.Fprintf(w, ", requested by %s", clean(s.RequestedBy, false))
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
	fmt.Printf("%s @ %s\nnamespaces: %s\npermission: %s\n", clean(w.Name, false), c.URL, clean(strings.Join(w.Namespaces, ", "), false), clean(w.Perm(), false))
	if w.ExpiryKnown {
		fmt.Printf("expires: %s\n", expiresText(w.ExpiresAt, clockNow()))
	}
	return nil
}

// expiresText is whoami's expiry: "2027-01-30 (in 90 days)" or "never".
func expiresText(t *time.Time, now time.Time) string {
	if t == nil {
		return "never"
	}
	d := t.UTC().Format("2006-01-02")
	if !now.Before(*t) {
		return d + " (expired)"
	}
	n := client.DaysLeft(*t, now)
	if n == 1 {
		return d + " (in 1 day)"
	}
	return fmt.Sprintf("%s (in %d days)", d, n)
}

// ---- renew ----

// cmdRenew asks the admin to renew this token, and with --wait waits for
// the approval and saves the new token. Nothing renews without the admin.
func cmdRenew(args []string) error {
	fs := flag.NewFlagSet("renew", flag.ExitOnError)
	wait := fs.Bool("wait", false, "wait for the admin to approve, then save the new token")
	timeout := fs.Duration("timeout", time.Hour, "how long --wait waits")
	parse(fs, args)
	c, err := newClient()
	if err != nil {
		return err
	}
	c.NoExpiryWarning = true
	st, err := c.Renew()
	if err != nil {
		return renewErr(err)
	}
	switch st.State {
	case "never":
		fmt.Println("keydrop: this token doesn't expire, so there's nothing to renew.")
		return nil
	case "approved":
		return collected(c)
	case "pending":
		if st.Created {
			fmt.Println("keydrop: renewal requested. Ask the admin to approve it in keydrop's Inbox.")
		} else {
			fmt.Println("keydrop: a renewal request is already waiting for the admin in keydrop's Inbox.")
		}
	default:
		return fmt.Errorf("the server answered an unexpected renewal state %q", clean(st.State, false))
	}
	if !*wait {
		fmt.Println("Run `keydrop renew --wait` to wait for it and save the new token.")
		return nil
	}
	if c.TokenPath == "" {
		return client.ErrRenewedNoFile
	}
	fmt.Println("Waiting for the admin…")
	deadline := time.Now().Add(*timeout)
	for time.Now().Before(deadline) {
		time.Sleep(renewPoll)
		st, err := c.RenewStatus()
		if err != nil {
			return renewErr(err)
		}
		switch st.State {
		case "approved":
			return collected(c)
		case "pending":
			continue
		}
		return errors.New("the admin declined the renewal request (or it was dropped); ask them, or run `keydrop renew` again")
	}
	return fmt.Errorf("still not approved after %s; the request stays in the Inbox. Run `keydrop renew --wait` again to keep waiting", *timeout)
}

// renewPoll is how often renew --wait checks.
var renewPoll = 5 * time.Second

// collected collects the renewed token, then uses it once, which makes it
// the only one that works.
func collected(c *client.Client) error {
	if _, err := c.Collect(); err != nil {
		return err
	}
	w, err := c.Whoami()
	if err != nil {
		return err
	}
	if w.ExpiryKnown {
		fmt.Printf("expires: %s\n", expiresText(w.ExpiresAt, clockNow()))
	}
	return nil
}

func renewErr(err error) error {
	var ae *client.APIError
	if errors.As(err, &ae) && ae.Status == http.StatusUnauthorized {
		return errors.New("this token can't be renewed: it's unknown, revoked, or expired more than 30 days ago. Pair this machine again: keydrop pair --url URL")
	}
	return err
}

// quote prints agent-written text indented behind "| ", so it can't pass
// for keydrop's own output.
func quote(w io.Writer, text string) {
	for _, l := range strings.Split(clean(text, true), "\n") {
		fmt.Fprintln(w, "      | "+l)
	}
}

func plural(n int) string {
	if n == 1 {
		return ""
	}
	return "s"
}

// cmdList lists secrets ("secrets") or variables ("vars"), never both, so
// an agent asking for settings doesn't get a list of keys mixed in.
func cmdList(kind string, args []string) error {
	fs := flag.NewFlagSet(kind, flag.ExitOnError)
	onlyNew := fs.Bool("new", false, "only ones whose value this token hasn't read since it last changed")
	pending := new(bool)
	if kind == "secret" {
		pending = fs.Bool("pending", false, "only requested secrets still waiting for a value")
	}
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
	all, err := c.List(q)
	if err != nil {
		return err
	}
	var list []client.Secret
	for _, s := range all {
		if s.Kind == kind {
			list = append(list, s)
		}
	}
	printList(os.Stdout, list)
	return nil
}

// printList prints secrets under group headings: "[ns: Name]" for the
// admin's groups, "[ns: PREFIX, auto]" for ones grouped by name, and
// "[ns: ungrouped]" last. With no groups at all it's a plain list.
func printList(w io.Writer, list []client.Secret) {
	if len(list) == 0 {
		fmt.Fprintln(w, "(none)")
		return
	}
	grouped := false
	for _, s := range list {
		grouped = grouped || s.Group != nil
	}
	if !grouped {
		for _, s := range list {
			printSecret(w, s, false)
		}
		return
	}
	rank := func(s client.Secret) int {
		switch {
		case s.Group == nil:
			return 2
		case s.Group.Auto:
			return 1
		}
		return 0
	}
	name := func(s client.Secret) string {
		if s.Group == nil {
			return ""
		}
		return strings.ToLower(s.Group.Name) + "\x00" + s.Group.Slug
	}
	sorted := slices.Clone(list)
	slices.SortStableFunc(sorted, func(a, b client.Secret) int {
		if c := strings.Compare(a.Namespace, b.Namespace); c != 0 {
			return c
		}
		if c := rank(a) - rank(b); c != 0 {
			return c
		}
		return strings.Compare(name(a), name(b))
	})
	last := ""
	for _, s := range sorted {
		head := "[" + s.Namespace + ": ungrouped]"
		if g := s.Group; g != nil && g.Auto {
			head = "[" + s.Namespace + ": " + g.Name + ", auto]"
		} else if g != nil {
			head = "[" + s.Namespace + ": " + g.Name + "]"
		}
		if head = clean(head, false); head != last {
			fmt.Fprintln(w, head)
			last = head
		}
		printSecret(w, s, false)
	}
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

// cmdHistory lists changes to the keys this token can see, newest first:
// who did what, and when. It changes nothing on the server.
func cmdHistory(args []string) error {
	fs := flag.NewFlagSet("history", flag.ExitOnError)
	limit := fs.Int("limit", 20, "show at most this many changes (up to 1000)")
	since := fs.Duration("since", 0, "only changes newer than this, e.g. 72h")
	ns := fs.String("namespace", "", "only this namespace")
	quiet := fs.Bool("quiet", false, "print nothing when there are no changes")
	pos := parse(fs, args)
	if len(pos) > 1 {
		return errors.New("usage: keydrop history [NAME] [--limit 20] [--since 72h]")
	}
	name := ""
	if len(pos) == 1 {
		name = pos[0]
		if n, nm, ok := strings.Cut(name, "/"); ok {
			*ns, name = n, nm
		}
	}
	c, err := newClient()
	if err != nil {
		return err
	}
	events, err := c.History(*ns, name, *limit)
	if err != nil {
		return err
	}
	shown := 0
	for _, e := range events {
		if *since > 0 && time.Since(e.At) > *since {
			continue
		}
		line := e.At.Local().Format("2006-01-02 15:04") + "  " + clean(e.Ref, false) + "  " + clean(e.Action, false)
		if e.Detail != "" {
			line += " " + clean(e.Detail, false)
		}
		fmt.Println(line + "  by " + clean(e.Actor, false))
		shown++
	}
	if shown == 0 && !*quiet {
		fmt.Println("(no changes)")
	}
	return nil
}

// cmdInbox is the old name of history, kept for one release so session
// hooks that run `keydrop inbox --quiet` keep working.
func cmdInbox(args []string) error {
	fmt.Fprintln(os.Stderr, "keydrop: `inbox` is deprecated and will be removed; use `keydrop history --since 72h`")
	// inbox showed only what was new, so by default show only recent
	// changes, not the whole history. A --since given here wins.
	return cmdHistory(append([]string{"--since", "72h"}, args...))
}

// cmdAck is a no-op kept for one release: a value stops being new to a
// token when the token reads it, so there's nothing left to acknowledge.
func cmdAck(args []string) error {
	fmt.Fprintln(os.Stderr, "keydrop: `ack` is deprecated and does nothing; a value stops being new to this token once it reads it (run, get --to-file, get --raw)")
	return nil
}

// cmdFlag asks the admin to look at a key. The reason and link are the
// admin's only; other agents see who flagged it and when.
func cmdFlag(args []string) error {
	fs := flag.NewFlagSet("flag", flag.ExitOnError)
	reason := fs.String("reason", "", "why (seen only by the admin)")
	link := fs.String("link", "", "an http(s) link with more (seen only by the admin)")
	pos := parse(fs, args)
	if len(pos) >= 2 && *reason == "" {
		*reason = strings.Join(pos[1:], " ")
		pos = pos[:1]
	}
	if len(pos) != 1 {
		return errors.New(`usage: keydrop flag REF ["reason"] [--link URL]`)
	}
	c, err := newClient()
	if err != nil {
		return err
	}
	if err := c.Flag(pos[0], *reason, *link); err != nil {
		return err
	}
	fmt.Println("Flagged for the admin:", pos[0])
	return nil
}

// cmdStatus sets a key's status: ok, expired, revoked, leaked, or
// replaced-by NAME.
func cmdStatus(args []string) error {
	fs := flag.NewFlagSet("status", flag.ExitOnError)
	pos := parse(fs, args)
	usage := errors.New("usage: keydrop status REF ok|expired|revoked|leaked|replaced-by NAME")
	if len(pos) < 2 {
		return usage
	}
	status, repl := pos[1], ""
	switch {
	case status == "replaced-by" && len(pos) == 3:
		repl = pos[2]
	case len(pos) != 2:
		return usage
	}
	c, err := newClient()
	if err != nil {
		return err
	}
	if err := c.SetStatus(pos[0], status, repl); err != nil {
		return err
	}
	fmt.Println(pos[0], "is now", strings.TrimSpace(status+" "+repl))
	return nil
}

// cmdNote proposes a note. Other agents see it only once the admin
// approves it, at the link printed.
func cmdNote(args []string) error {
	fs := flag.NewFlagSet("note", flag.ExitOnError)
	pos := parse(fs, args)
	if len(pos) < 2 {
		return errors.New(`usage: keydrop note REF "text"   (- reads the text from stdin)`)
	}
	text := strings.Join(pos[1:], " ")
	if text == "-" {
		b, err := io.ReadAll(io.LimitReader(os.Stdin, store.MaxText+1))
		if err != nil {
			return err
		}
		text = string(b)
	}
	c, err := newClient()
	if err != nil {
		return err
	}
	link, err := c.Note(pos[0], text)
	if err != nil {
		return err
	}
	if link == "" {
		fmt.Println("Note sent. Other agents see it once the admin approves it on", pos[0]+"'s page.")
		return nil
	}
	fmt.Println("Note sent. Other agents see it once the admin approves it here:")
	fmt.Println(clean(link, false))
	return nil
}

func cmdRequest(args []string) error {
	fs := flag.NewFlagSet("request", flag.ExitOnError)
	desc := fs.String("desc", "", "what it's for and how to create it (shown to the human)")
	use := fs.String("usage", "", "how it'll be used, e.g. 'Authorization: Bearer {}'")
	group := fs.String("group", "", "a group name to suggest for these keys (the human decides)")
	pos := parse(fs, args)
	if len(pos) == 0 || *desc == "" {
		return errors.New("usage: keydrop request REF [REF...] [--group NAME] --desc \"what it's for, which scopes, how long it should last\"")
	}
	if len(pos) > maxBatch {
		return fmt.Errorf("one request can name at most %d keys; split it up", maxBatch)
	}
	c, err := newClient()
	if err != nil {
		return err
	}
	if len(pos) == 1 && *group == "" {
		link, err := c.Request(pos[0], *desc, *use)
		if err != nil {
			return err
		}
		fmt.Println("Requested. The human can fill it in here:")
		fmt.Println(clean(link, false))
		fmt.Println("Then: keydrop wait " + pos[0])
		return nil
	}
	b, err := c.RequestBatch(pos, *group, *desc, *use)
	if err != nil {
		return err
	}
	fmt.Printf("Requested %d key%s together. The human fills them in on one card", len(b.Refs), plural(len(b.Refs)))
	if b.URL != "" {
		fmt.Println(" here:")
		fmt.Println(clean(b.URL, false))
	} else {
		fmt.Println(".")
	}
	if *group != "" {
		fmt.Println("The group you suggested is shown to the human, who decides whether to use it.")
	}
	for _, ref := range b.Refs {
		fmt.Println("Then: keydrop wait " + clean(ref, false))
	}
	return nil
}

// maxBatch matches the server's limit on keys per request.
const maxBatch = store.MaxBatch

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
	days := fs.Int("days", 14, "look this many days ahead (0 to 36500)")
	check := fs.Bool("check", false, "exit 1 if anything is expiring (for health checks)")
	parse(fs, args)
	if *days < 0 || *days > 36500 {
		return errors.New("--days must be between 0 and 36500")
	}
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

// warnStatus says on stderr when a key about to be used is marked expired,
// revoked, leaked or replaced. It doesn't stop anything.
func warnStatus(ref string, st *store.Status) {
	if st == nil {
		return
	}
	fmt.Fprintf(os.Stderr, "keydrop: warning: %s is marked %s (by %s, %s)\n", ref, clean(st.String(), false), clean(st.By, false), st.At.Local().Format("2006-01-02"))
}

type multiFlag []string

func (m *multiFlag) String() string     { return strings.Join(*m, ",") }
func (m *multiFlag) Set(v string) error { *m = append(*m, v); return nil }

var envNameRE = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

type binding struct{ envVar, ref string }

// errEnvFlag never echoes the flag: an agent used to docker's -e VAR=value
// may have put a value there.
var errEnvFlag = errors.New("-e takes a secret's name (NAME, ns/NAME or VAR=NAME), never a value")

// parseEnvFlag reads one -e value: NAME or ns/NAME injects the secret under
// its own name, VAR=REF under another.
func parseEnvFlag(e string) (binding, error) {
	v, ref, renamed := strings.Cut(e, "=")
	if !renamed {
		ref = e
	}
	ns, name, scoped := strings.Cut(ref, "/")
	if !scoped {
		ns, name = "", ref
	}
	switch {
	case scoped && !store.ValidName(ns), !store.ValidSecretName(name):
		return binding{}, errEnvFlag
	case renamed && !envNameRE.MatchString(v):
		return binding{}, errEnvFlag
	case !renamed:
		v = name
	}
	return binding{v, ref}, nil
}

// childEnv is the command's environment: ours without any KEYDROP_*
// settings (the token, where the token file is, the URL and pin), plus the
// secrets (which win over inherited variables of the same name). A secret
// bound to a KEYDROP_ name is still passed, since it was asked for.
//
// This keeps the token out of the child's way, not out of its reach: the
// child runs as the same user and can read the token file. run isn't a
// sandbox.
func childEnv(environ []string, binds []binding, values map[string]string) []string {
	var env []string
	for _, kv := range environ {
		if !strings.HasPrefix(kv, "KEYDROP_") {
			env = append(env, kv)
		}
	}
	for _, b := range binds {
		env = append(env, b.envVar+"="+values[b.ref])
	}
	return env
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
	if *noMask {
		// Recorded, and first so a long command name can't push it past the
		// audit log's field limit.
		purpose = "run --no-mask " + filepath.Base(argv[0])
	}
	values := map[string]string{}
	var m mask.Masker
	for ref := range refs {
		rv, err := c.RevealStatus(ref, purpose)
		if err != nil {
			return 0, fmt.Errorf("%s: %w", ref, err)
		}
		v, variable := rv.Value, rv.Kind == "variable"
		warnStatus(ref, rv.Status)
		if strings.ContainsRune(v, 0) {
			return 0, fmt.Errorf("%s: the value contains a NUL byte, which can't go in an environment variable; use get --to-file", ref)
		}
		values[ref] = v
		if variable {
			continue // not secret, so not masked
		}
		if !m.Add(ref, []byte(v)) && !*noMask {
			fmt.Fprintf(os.Stderr, "keydrop: warning: %s is shorter than %d characters and won't be masked\n", ref, mask.MinLength)
		}
	}

	cmd := exec.Command(argv[0], argv[1:]...)
	cmd.Env = childEnv(os.Environ(), binds, values)
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
	if len(pos) != 1 || (*toFile != "" && *raw) {
		return errors.New("usage: keydrop get NAME   (variables; secrets need --to-file PATH, or --raw, which leaks it into logs)")
	}
	c, err := newClient()
	if err != nil {
		return err
	}
	if *toFile == "" && !*raw {
		// Metadata only, so asking for a secret this way isn't logged as a read.
		sec, err := c.Get(pos[0])
		if err != nil {
			return err
		}
		if sec.Kind == "variable" && sec.Value == nil {
			return fmt.Errorf("%s has no value yet", sec.Ref)
		}
		if sec.Value == nil {
			return fmt.Errorf("%s is a secret, so it isn't printed: use keydrop run -e %s, or get --to-file for a file", sec.Ref, sec.Name)
		}
		v := *sec.Value
		if sec.New {
			// Reading it through reveal is what marks it as no longer
			// new to this token (a variable's reads aren't logged).
			rv, err := c.RevealStatus(sec.Ref, "get")
			if err != nil {
				return err
			}
			v = rv.Value
		}
		fmt.Println(forTerminal(v))
		return nil
	}
	purpose := "get --raw"
	if *toFile != "" {
		purpose = "get --to-file"
	}
	rv, err := c.RevealStatus(pos[0], purpose)
	if err != nil {
		return err
	}
	v, variable := rv.Value, rv.Kind == "variable"
	warnStatus(pos[0], rv.Status)
	if *raw {
		if !variable {
			fmt.Fprintln(os.Stderr, "keydrop: printing a secret; it's now in this terminal's output")
		}
		fmt.Print(forTerminal(v))
		return nil
	}
	if err := writeValueFile(*toFile, v, *force); err != nil {
		return err
	}
	fmt.Println("wrote", pos[0], "to", *toFile)
	return nil
}

// writeValueFile writes v to path with mode 600. Without force it refuses
// an existing path (a symlink included). With force it writes a new file
// beside it and renames it into place, so the result is always a fresh
// 0600 file: an existing file's looser mode isn't kept, and a symlink at
// path is replaced, not followed.
func writeValueFile(path, v string, force bool) error {
	if !force {
		f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
		if err != nil {
			return err
		}
		if _, err := f.WriteString(v); err != nil {
			f.Close()
			os.Remove(path)
			return err
		}
		return f.Close()
	}
	if fi, err := os.Lstat(path); err == nil && fi.IsDir() {
		return fmt.Errorf("%s is a directory", path)
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".keydrop-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.WriteString(v); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}

// forTerminal is v as is when stdout is a pipe or file (scripts get exact
// bytes), and quoted if it holds escapes when stdout is a terminal.
func forTerminal(v string) string {
	if isTerminal(os.Stdout) {
		return printable(v)
	}
	return v
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

// maxPutValue is the largest value put accepts: the server takes request
// bodies up to 128 KiB, and JSON escaping can double a value's size.
const maxPutValue = 60 << 10

func cmdPut(args []string) error {
	fs := flag.NewFlagSet("put", flag.ExitOnError)
	desc := fs.String("desc", "", "description")
	use := fs.String("usage", "", "usage hint")
	expires := fs.String("expires", "", "expiry date, e.g. 2027-01-23")
	overwrite := fs.Bool("overwrite", false, "replace an existing value")
	keepWS := fs.Bool("keep-ws", false, "keep leading/trailing whitespace")
	asVar := fs.Bool("var", false, "store it as a variable (not secret: agents can print it)")
	pos := parse(fs, args)
	if len(pos) != 1 {
		return errors.New("usage: keydrop put REF [--var] [--desc TEXT] < value   (the value comes from stdin, never the command line)")
	}
	var v string
	if isTerminal(os.Stdin) {
		line, err := readSecretLine("Value: ")
		if err != nil {
			return err
		}
		v = line
	} else {
		b, err := io.ReadAll(io.LimitReader(os.Stdin, maxPutValue+1))
		if err != nil {
			return err
		}
		if len(b) > maxPutValue {
			return fmt.Errorf("the value is over %d KiB; keydrop is for credentials, not files", maxPutValue>>10)
		}
		v = string(b)
	}
	if !utf8.ValidString(v) {
		// JSON would silently replace the invalid bytes.
		return errors.New("the value isn't text (not valid UTF-8); store binary values base64-encoded, e.g. base64 < key.bin | keydrop put REF")
	}
	if !*keepWS {
		v = strings.TrimSpace(v)
	}
	if v == "" {
		return errors.New("empty value")
	}
	o := client.PutOptions{Overwrite: *overwrite, Variable: *asVar}
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
	asVars := fs.Bool("vars", false, "import everything as variables (not secret); default is secrets")
	pos := parse(fs, args)
	if len(pos) != 1 {
		return errors.New("usage: keydrop import FILE [--namespace NS] [--vars] [--dry-run]")
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
		o := client.PutOptions{Description: &desc, Overwrite: *overwrite, Variable: *asVars}
		err := c.Put(ref, e.value, o)
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
	dir, err := saveLogin(*u, tok, *pin)
	if err != nil {
		return err
	}
	fmt.Printf("Logged in as %s (namespaces: %s). Saved to %s\n", clean(w.Name, false), clean(strings.Join(w.Namespaces, ", "), false), dir)
	return nil
}

// saveLogin writes the url, token and pin files (mode 600).
func saveLogin(u, tok, pin string) (string, error) {
	dir := client.ConfigDir()
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", err
	}
	files := map[string]string{"url": u, "token": tok}
	if pin != "" {
		files["pin"] = pin
	} else {
		os.Remove(filepath.Join(dir, "pin"))
	}
	for name, v := range files {
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, []byte(v+"\n"), 0o600); err != nil {
			return "", err
		}
		if err := os.Chmod(path, 0o600); err != nil { // WriteFile keeps an existing file's mode
			return "", err
		}
	}
	return dir, nil
}

// pendingPair is a pairing request in progress, kept so that running
// `keydrop pair` again carries on waiting instead of asking again.
type pendingPair struct {
	URL, Pin, Poll, Code, Link string
	Expires                    time.Time
}

func cmdPair(args []string) error {
	fs := flag.NewFlagSet("pair", flag.ExitOnError)
	u := fs.String("url", "", "server URL, e.g. https://10.0.0.5:8443")
	pin := fs.String("pin", "", "certificate pin for a self-signed server (sha256:…, printed in the server log)")
	wait := fs.Duration("timeout", 10*time.Minute, "how long to wait for approval")
	fresh := fs.Bool("new", false, "start a new request even if one is waiting")
	parse(fs, args)
	dir := client.ConfigDir()
	statePath := filepath.Join(dir, "pairing")

	var p pendingPair
	if fi, err := os.Stat(statePath); err == nil && !*fresh && fi.Mode().Perm()&0o077 != 0 {
		return fmt.Errorf("%s is readable by other users; delete it and run keydrop pair --url URL again", statePath)
	}
	if b, err := os.ReadFile(statePath); err == nil && !*fresh {
		if json.Unmarshal(b, &p) != nil || time.Now().After(p.Expires) || (*u != "" && *u != p.URL) {
			p = pendingPair{}
		}
	}
	if p.Poll == "" && *u == "" {
		return errors.New("usage: keydrop pair --url URL [--pin sha256:…]")
	}
	if p.Poll == "" {
		if strings.HasPrefix(*u, "http://") {
			fmt.Fprintln(os.Stderr, "warning: plain http, so the token crosses the network unencrypted")
		}
		c := client.New(*u, "", *pin)
		host, _ := os.Hostname()
		name := ""
		if me, err := user.Current(); err == nil {
			name = me.Username
		}
		res, err := c.Pair(host, name)
		if err != nil {
			return err
		}
		link := res.Link
		if link == "" {
			link = strings.TrimRight(*u, "/") + res.Path
		}
		p = pendingPair{URL: *u, Pin: *pin, Poll: res.Poll, Code: res.Code, Link: link,
			Expires: time.Now().Add(time.Duration(res.ExpiresIn) * time.Second)}
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return err
		}
		b, _ := json.Marshal(p)
		if err := os.WriteFile(statePath, b, 0o600); err != nil {
			return err
		}
		if err := os.Chmod(statePath, 0o600); err != nil { // WriteFile keeps an existing file's mode
			return err
		}
		fmt.Printf("Ask the keydrop admin to approve this machine. Send them this link:\n\n  %s\n\nThe page will show the code %s. The request expires at %s.\n",
			clean(p.Link, false), clean(p.Code, false), p.Expires.Local().Format("15:04"))
	} else {
		fmt.Printf("Still waiting for approval of code %s: %s\n", clean(p.Code, false), clean(p.Link, false))
	}
	fmt.Println("Waiting… (if this is interrupted, run keydrop pair again to keep waiting)")

	c := client.New(p.URL, "", p.Pin)
	deadline := time.Now().Add(*wait)
	for {
		res, err := c.PairPoll(p.Poll)
		if client.IsNotFound(err) {
			os.Remove(statePath)
			return errors.New("the request expired or was denied; run keydrop pair --url URL to ask again")
		}
		if err != nil {
			return err
		}
		if res.State == "approved" {
			os.Remove(statePath)
			if _, err := saveLogin(p.URL, res.Token, p.Pin); err != nil {
				return fmt.Errorf("approved, but saving the token failed (ask the admin to revoke %s and pair again): %w", res.Name, err)
			}
			fmt.Printf("Approved as %s (namespaces: %s). Saved to %s\n", clean(res.Name, false), clean(strings.Join(res.Namespaces, ", "), false), dir)
			return nil
		}
		if time.Now().After(deadline) {
			return errors.New("not approved yet; run keydrop pair again to keep waiting")
		}
		time.Sleep(2 * time.Second)
	}
}

// printable quotes a variable's value if it holds anything but printable
// characters, so a value with a newline, a terminal escape or a
// bidirectional override can't fake output in an agent's terminal.
func printable(v string) string {
	if strings.IndexFunc(v, func(r rune) bool { return !strconv.IsPrint(r) }) >= 0 || !utf8.ValidString(v) {
		return strconv.Quote(v)
	}
	return v
}

// clean makes text from the server safe to print: control characters
// (terminal escapes included), bidirectional overrides and other
// non-printing characters are shown as \x.. / \u.... escapes, so they're
// visible and inert. multiline keeps newlines; tabs become spaces.
func clean(s string, multiline bool) string {
	var b strings.Builder
	for len(s) > 0 {
		r, size := utf8.DecodeRuneInString(s)
		switch {
		case r == utf8.RuneError && size == 1: // not UTF-8
			fmt.Fprintf(&b, "\\x%02x", s[0])
		case r == '\n' && multiline:
			b.WriteByte('\n')
		case r == '\t':
			b.WriteByte(' ')
		case r < 0x80 && !strconv.IsPrint(r):
			fmt.Fprintf(&b, "\\x%02x", r)
		case !strconv.IsPrint(r):
			fmt.Fprintf(&b, "\\u%04x", r)
		default:
			b.WriteRune(r)
		}
		s = s[size:]
	}
	return b.String()
}
