package main

import (
	"context"
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/minituff/keydrop/internal/audit"
	"github.com/minituff/keydrop/internal/server"
	"github.com/minituff/keydrop/internal/store"
)

func env(name, def string) string {
	if v, ok := os.LookupEnv(name); ok && v != "" {
		return v
	}
	return def
}

func envBool(name string, def bool) bool {
	switch strings.ToLower(env(name, "")) {
	case "1", "true", "yes", "on":
		return true
	case "0", "false", "no", "off":
		return false
	}
	return def
}

// masterKey reads KEYDROP_MASTER_KEY_FILE (preferred: a Docker secret) or
// KEYDROP_MASTER_KEY.
func masterKey() ([]byte, error) {
	if path := env("KEYDROP_MASTER_KEY_FILE", ""); path != "" {
		b, err := os.ReadFile(path)
		if err != nil {
			return nil, err
		}
		if fi, err := os.Stat(path); err == nil && fi.Mode().Perm()&0o077 != 0 {
			// Docker secrets are often 0444 inside the container and that's
			// the runtime's business, so warn rather than refuse.
			log.Printf("warning: master key file %s is mode %04o; make it readable by keydrop's user only (0400 or 0600)", path, fi.Mode().Perm())
		}
		return store.ParseKey(string(b))
	}
	if k := env("KEYDROP_MASTER_KEY", ""); k != "" {
		return store.ParseKey(k)
	}
	return nil, errors.New("set KEYDROP_MASTER_KEY_FILE (or KEYDROP_MASTER_KEY); generate a key with `keydrop genkey`")
}

func cmdGenkey(args []string) error {
	fmt.Println(store.GenerateKey())
	return nil
}

// cmdHealthcheck probes the local server. Docker runs it inside the
// container, which has no shell or curl.
func cmdHealthcheck(args []string) error {
	listen := env("KEYDROP_LISTEN", ":8443")
	_, port, err := net.SplitHostPort(listen)
	if err != nil {
		return err
	}
	scheme := "https"
	if env("KEYDROP_TLS", "auto") == "off" {
		scheme = "http"
	}
	c := &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{
		// Loopback only, and /healthz carries nothing secret.
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}}
	resp, err := c.Get(scheme + "://127.0.0.1:" + port + "/healthz")
	if err != nil {
		return err
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("healthz returned %s", resp.Status)
	}
	return nil
}

// directAddress is the URL agents use to reach keydrop itself: the first IP
// in KEYDROP_TLS_HOSTS (names usually point at a proxy), else the first name.
func directAddress(hosts []string, listen string) string {
	_, port, err := net.SplitHostPort(listen)
	if err != nil || len(hosts) == 0 {
		return ""
	}
	pick := hosts[0]
	for _, h := range hosts {
		if net.ParseIP(h) != nil {
			pick = h
			break
		}
	}
	return "https://" + net.JoinHostPort(pick, port)
}

// dataCommand opens the data directory for one of the offline data
// commands, with the same environment as the server.
func dataCommand(name string, args []string) (string, *store.Store, error) {
	fs := flag.NewFlagSet(name, flag.ExitOnError)
	fs.Parse(args)
	if fs.NArg() > 0 {
		return "", nil, fmt.Errorf("%s takes no arguments; it's configured like the server (KEYDROP_DATA_DIR, KEYDROP_MASTER_KEY_FILE)", name)
	}
	dataDir := env("KEYDROP_DATA_DIR", "/data")
	key, err := masterKey()
	if err != nil {
		return "", nil, err
	}
	st, err := store.OpenExisting(dataDir, key) // checks the key, and the HMAC if there is one
	if err != nil {
		return "", nil, err
	}
	return dataDir, st, nil
}

// cmdUpgradeData moves a data directory written by a release before the
// integrity check to the current format: keydrop.json gets its HMAC and
// tls.key is sealed (same key and certificate, so the pin doesn't change).
// The server never does this on its own: the old format can't be checked,
// so upgrading vouches for the files exactly as they are, and that's the
// operator's call. Run it once, with the server stopped and the same
// environment as the server. Running it again changes nothing.
func cmdUpgradeData(args []string) error {
	dataDir, st, err := dataCommand("upgrade-data", args)
	if err != nil {
		return err
	}
	changed, err := st.Upgrade()
	if err != nil {
		return err
	}
	if changed {
		fmt.Printf("keydrop.json: added the integrity check (HMAC)\n")
	} else {
		fmt.Printf("keydrop.json: already has the integrity check, unchanged\n")
	}
	fp, sealed, err := server.SealTLSKey(dataDir, st)
	switch {
	case err != nil:
		return fmt.Errorf("tls.key: %w", err)
	case fp == "":
		fmt.Printf("tls.key: none in %s (KEYDROP_TLS=files or off), nothing to seal\n", dataDir)
	case sealed:
		fmt.Printf("tls.key: sealed with the master key; same key and certificate\n")
	default:
		fmt.Printf("tls.key: already sealed, unchanged\n")
	}
	if fp != "" {
		fmt.Printf("Certificate pin (unchanged): %s\n", fp)
	}
	fmt.Printf("Done. Start keydrop with this release. To go back to the older one, run `keydrop downgrade-data` first.\n")
	if sealed {
		fmt.Printf("Backups of %s made before now still hold tls.key in plaintext: if one may have been exposed, run `keydrop rotate-tls` and re-pin the agents (see the README).\n", dataDir)
	}
	return nil
}

// cmdDowngradeData undoes what upgrade-data did, so a release before the
// sealed TLS key and integrity check can start on the data directory: the
// state file's key check goes back to the old format and tls.key is
// written back in plaintext. Run it with the server stopped, with the same
// environment as the server.
func cmdDowngradeData(args []string) error {
	dataDir, st, err := dataCommand("downgrade-data", args)
	if err != nil {
		return err
	}
	if st.FormatV4() {
		// One step at a time: back to the release before token expiry and
		// canaries. Running it again goes back further.
		d, _, err := st.DowngradeV4()
		if err != nil {
			return err
		}
		printDropped(d)
		fmt.Printf("Done: the release before token expiry and canaries can read this data directory; this release still can, and starts using the new fields again as soon as they're set.\n")
		fmt.Printf("Run downgrade-data again to go back to a release before the integrity check.\n")
		return nil
	}
	unsealed, err := server.UnsealTLSKey(dataDir, st)
	if err != nil {
		return fmt.Errorf("tls.key: %w", err)
	}
	if unsealed {
		fmt.Printf("tls.key: written back in plaintext; same key and certificate\n")
	} else {
		fmt.Printf("tls.key: not sealed (or none), unchanged\n")
	}
	changed, err := st.Downgrade()
	if err != nil {
		return err
	}
	if changed {
		fmt.Printf("keydrop.json: key check back in the old format\n")
	} else {
		fmt.Printf("keydrop.json: already in the old format, unchanged\n")
	}
	fmt.Printf("Done: the previous release can read this data directory. This release refuses it until `keydrop upgrade-data` is run again.\n")
	return nil
}

// cmdRotateTLS replaces the self-signed certificate with a new key and
// certificate, keeping the old files as timestamped backups. Every agent
// then needs the new pin. Run it with the server stopped (a running server
// keeps serving the old certificate until it restarts).
func cmdRotateTLS(args []string) error {
	if m := env("KEYDROP_TLS", "auto"); m != "auto" {
		return fmt.Errorf("rotate-tls is for the self-signed certificate (KEYDROP_TLS=auto), not KEYDROP_TLS=%s", m)
	}
	dataDir, st, err := dataCommand("rotate-tls", args)
	if err != nil {
		return err
	}
	if st.Legacy() {
		return store.ErrNeedsUpgrade
	}
	hosts := strings.FieldsFunc(env("KEYDROP_TLS_HOSTS", ""), func(r rune) bool { return r == ',' || r == ' ' })
	fp, backups, err := server.RotateSelfSigned(dataDir, hosts, st, time.Now())
	if err != nil {
		return err
	}
	fmt.Printf("New certificate made (sealed key). The old pair is kept as:\n")
	for _, b := range backups {
		fmt.Printf("  %s\n", b)
	}
	fmt.Printf("New pin: %s\n", fp)
	fmt.Printf("Start keydrop, then on each agent's machine, as the agent's user:\n")
	fmt.Printf("  keydrop login --url \"$(cat ~/.config/keydrop/url)\" --pin %s < ~/.config/keydrop/token\n", fp)
	fmt.Printf("(and replace KEYDROP_TLS_PIN wherever it's set). To undo before re-pinning anyone, stop keydrop and rename the .bak files back.\n")
	return nil
}

func cmdServer(args []string) error {
	fs := flag.NewFlagSet("server", flag.ExitOnError)
	fs.Parse(args)

	dataDir := env("KEYDROP_DATA_DIR", "/data")
	key, err := masterKey()
	if err != nil {
		return err
	}
	st, err := store.Open(dataDir, key)
	if err != nil {
		return err
	}
	if testClock != nil {
		st.SetClock(testClock)
	}
	al, err := audit.Open(filepath.Join(dataDir, "audit.jsonl"))
	if err != nil {
		return err
	}
	defer al.Close()

	var proxies []netip.Prefix
	for _, p := range strings.FieldsFunc(env("KEYDROP_TRUSTED_PROXIES", ""), func(r rune) bool { return r == ',' || r == ' ' }) {
		pfx, err := netip.ParsePrefix(p)
		if err != nil {
			addr, err2 := netip.ParseAddr(p)
			if err2 != nil {
				return fmt.Errorf("KEYDROP_TRUSTED_PROXIES: %q is not an IP or CIDR", p)
			}
			pfx = netip.PrefixFrom(addr, addr.BitLen())
		}
		proxies = append(proxies, pfx)
	}

	tlsMode := env("KEYDROP_TLS", "auto")
	listen := env("KEYDROP_LISTEN", ":8443")
	var tlsCert *tls.Certificate
	var certPin, keyPin, directURL string
	switch tlsMode {
	case "auto":
		hosts := strings.FieldsFunc(env("KEYDROP_TLS_HOSTS", ""), func(r rune) bool { return r == ',' || r == ' ' })
		c, fp, err := server.LoadOrCreateSelfSigned(dataDir, hosts, st)
		if err != nil {
			return fmt.Errorf("self-signed certificate: %w", err)
		}
		tlsCert = &c
		certPin = fp
		if keyPin, err = server.KeyPin(c.Certificate[0]); err != nil {
			return err
		}
		directURL = directAddress(hosts, listen)
		log.Printf("TLS: self-signed certificate. Agents pin it with KEYDROP_TLS_PIN=%s", fp)
	case "files":
		c, err := tls.LoadX509KeyPair(env("KEYDROP_TLS_CERT", ""), env("KEYDROP_TLS_KEY", ""))
		if err != nil {
			return fmt.Errorf("KEYDROP_TLS=files: %w", err)
		}
		tlsCert = &c
	case "off":
		log.Printf("TLS is off: only do this behind a reverse proxy that terminates TLS")
	default:
		return fmt.Errorf("KEYDROP_TLS must be auto, files or off, not %q", tlsMode)
	}

	publicURL := env("KEYDROP_PUBLIC_URL", "")
	guessed := publicURL == ""
	if guessed {
		scheme := "https"
		if tlsCert == nil {
			scheme = "http"
		}
		host, port, err := net.SplitHostPort(listen)
		if err != nil || host == "" || host == "0.0.0.0" || host == "::" {
			host = "localhost"
		}
		publicURL = scheme + "://" + net.JoinHostPort(host, port)
		log.Printf("KEYDROP_PUBLIC_URL isn't set; links will use %s", publicURL)
	}

	if directURL == "" && certPin != "" {
		directURL = publicURL
	}
	cli, err := server.LoadCLI(env("KEYDROP_CLI_DIR", ""))
	if err != nil {
		return fmt.Errorf("KEYDROP_CLI_DIR: %w", err)
	}

	webhook := env("KEYDROP_ALERT_WEBHOOK", "")
	if err := server.CheckAlertWebhook(webhook); err != nil {
		return err
	}
	if webhook != "" {
		log.Printf("canary alerts: webhook configured")
	}

	cfg := server.Config{
		AlertWebhook:   webhook,
		Now:            testClock,
		PublicURL:      publicURL,
		PublicURLGuess: guessed,
		CookieSecure:   envBool("KEYDROP_COOKIE_SECURE", true),
		TrustedProxies: proxies,
		ResetAdmin:     envBool("KEYDROP_RESET_ADMIN", false),
		Version:        version,
		Commit:         commit,
		CommitTime:     commitTime,
		RepoURL:        repoURL,
		CLI:            cli,
		CertPin:        certPin,
		KeyPin:         keyPin,
		DirectURL:      directURL,
	}
	srv := server.New(cfg, st, al)
	if public, direct := cfg.InstallCommands(); public != "" || direct != "" {
		log.Printf("install the CLI on an agent's machine with one of:")
		for _, c := range []string{public, direct} {
			if c != "" {
				log.Printf("  %s", c)
			}
		}
	}

	hs := &http.Server{
		Addr:              listen,
		Handler:           srv,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       2 * time.Minute,
		ErrorLog:          log.New(os.Stderr, "http: ", 0),
	}
	if tlsCert != nil {
		hs.TLSConfig = &tls.Config{Certificates: []tls.Certificate{*tlsCert}, MinVersion: tls.VersionTLS12}
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	errc := make(chan error, 1)
	go func() {
		log.Printf("keydrop %s listening on %s", version, listen)
		if tlsCert != nil {
			errc <- hs.ListenAndServeTLS("", "")
		} else {
			errc <- hs.ListenAndServe()
		}
	}()
	select {
	case err := <-errc:
		return err
	case <-ctx.Done():
		log.Printf("shutting down")
		sctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		return hs.Shutdown(sctx)
	}
}

// printDropped lists, by name only, what DowngradeV4 removed.
func printDropped(d store.V4Dropped) {
	list := func(what string, names []string) {
		if len(names) > 0 {
			fmt.Printf("%s: %s\n", what, strings.Join(names, ", "))
		}
	}
	list("tokens that no longer expire", d.Expiring)
	list("renewal requests dropped", d.Renewals)
	list("tokens deleted (renewed, new token never collected; pair these agents again)", d.Unpaired)
	list("renewals completed (only the new token works)", d.Rotations)
	list("secrets no longer canaries", d.Canaries)
	if d.CanaryHits > 0 {
		fmt.Printf("canary alerts dropped from the Inbox: %d (still in the audit log)\n", d.CanaryHits)
	}
	if d.RevokeOn {
		fmt.Printf("\"revoke a token that reads a canary\" was on; it's gone\n")
	}
	if len(d.Expiring)+len(d.Renewals)+len(d.Unpaired)+len(d.Rotations)+len(d.Canaries)+d.CanaryHits == 0 && !d.RevokeOn {
		fmt.Printf("keydrop.json: nothing from token expiry or canaries was in use\n")
	}
	fmt.Printf("keydrop.json: key check back to the format before token expiry and canaries\n")
}
