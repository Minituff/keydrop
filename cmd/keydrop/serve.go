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
	"github.com/minituff/keydrop/internal/notify"
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
	var tlsCert *tls.Certificate
	switch tlsMode {
	case "auto":
		hosts := strings.FieldsFunc(env("KEYDROP_TLS_HOSTS", ""), func(r rune) bool { return r == ',' || r == ' ' })
		c, fp, err := server.LoadOrCreateSelfSigned(dataDir, hosts)
		if err != nil {
			return fmt.Errorf("self-signed certificate: %w", err)
		}
		tlsCert = &c
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

	listen := env("KEYDROP_LISTEN", ":8443")
	publicURL := env("KEYDROP_PUBLIC_URL", "")
	if publicURL == "" {
		scheme := "https"
		if tlsCert == nil {
			scheme = "http"
		}
		publicURL = scheme + "://localhost" + listen
		log.Printf("KEYDROP_PUBLIC_URL isn't set; links will use %s", publicURL)
	}

	srv := server.New(server.Config{
		PublicURL:      publicURL,
		CookieSecure:   envBool("KEYDROP_COOKIE_SECURE", true),
		TrustedProxies: proxies,
		ResetAdmin:     envBool("KEYDROP_RESET_ADMIN", false),
		Notifier: &notify.Notifier{
			URL:    env("KEYDROP_WEBHOOK_URL", ""),
			Format: env("KEYDROP_WEBHOOK_FORMAT", "json"),
		},
	}, st, al)

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
