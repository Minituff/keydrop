package main

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"

	"github.com/minituff/keydrop/internal/client"
)

// cmdUpgrade replaces this binary with the build the paired server hands
// out, the same one install.sh fetches: over the configured URL and pin,
// checked against the server's SHA256SUMS, and run once (`version`) before
// it replaces anything. The old binary stays next to it as .<version>.bak.
//
// It asks the server first, with the token, and stops unless the admin
// allows this agent to upgrade itself. That's advisory (a machine can
// always replace its own files), but it's what tells an agent to leave
// it to the user.
//
// SHA256SUMS comes over the same connection as the build, so it catches a
// cut-off or corrupted download, not a malicious server: the pin is what
// says this is the right server.
func cmdUpgrade(args []string) error {
	fs := flag.NewFlagSet("upgrade", flag.ExitOnError)
	force := fs.Bool("force", false, "reinstall even if the server's build is this one")
	if len(parse(fs, args)) > 0 {
		return errors.New("usage: keydrop upgrade [--force]")
	}
	c, err := client.FromEnv()
	if err != nil {
		return fmt.Errorf("%w (keydrop upgrade checks with the server that this agent may upgrade itself; without a token, reinstall from the server's /install.sh instead)", err)
	}
	allowed, err := c.AskUpgrade(version)
	if err != nil {
		return fmt.Errorf("asking the server whether this agent may upgrade itself: %w", err)
	}
	if !allowed {
		return errors.New("self-upgrade is off for this agent, so don't update the CLI yourself: tell the user, who can upgrade it or turn self-upgrade on for this agent under Agents")
	}
	name := "keydrop-" + runtime.GOOS + "-" + runtime.GOARCH
	if runtime.GOOS == "windows" {
		name += ".exe"
	}
	exe, err := os.Executable()
	if err == nil {
		exe, err = filepath.EvalSymlinks(exe)
	}
	if err != nil {
		return fmt.Errorf("can't find this binary to replace it: %w", err)
	}
	fi, err := os.Stat(exe)
	if err != nil {
		return err
	}

	var sums bytes.Buffer
	if err := c.Download("/cli/SHA256SUMS", &sums, 64<<10); err != nil {
		return fmt.Errorf("fetching the server's SHA256SUMS: %w", err)
	}
	want := sumFor(sums.String(), name)
	if want == "" {
		return fmt.Errorf("the server has no %s build to upgrade to", name)
	}

	// In the same directory, so the final rename can't cross filesystems.
	tmp, err := os.CreateTemp(filepath.Dir(exe), ".keydrop-upgrade-*")
	if err != nil {
		return fmt.Errorf("can't write next to %s (%v); reinstall with the server's /install.sh instead", exe, err)
	}
	defer os.Remove(tmp.Name()) // a no-op once it's been moved into place
	h := sha256.New()
	err = c.Download("/cli/"+name, io.MultiWriter(tmp, h), 512<<20)
	if cerr := tmp.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return fmt.Errorf("downloading %s: %w", name, err)
	}
	if got := hex.EncodeToString(h.Sum(nil)); got != want {
		return fmt.Errorf("%s doesn't match the server's SHA256SUMS (got %s, want %s); nothing was replaced", name, got, want)
	}
	if err := os.Chmod(tmp.Name(), fi.Mode().Perm()|0o700); err != nil {
		return err
	}
	out, err := exec.Command(tmp.Name(), "version").Output()
	newVersion, ok := strings.CutPrefix(strings.TrimSpace(string(out)), "keydrop ")
	if err != nil || !ok || newVersion == "" {
		return fmt.Errorf("the downloaded build doesn't run here (%v); nothing was replaced", err)
	}
	newVersion = clean(newVersion, false)
	if newVersion == version && !*force {
		fmt.Printf("keydrop is already %s, the server's build.\n", version)
		return nil
	}

	bak := exe + "." + bakSafe.ReplaceAllString(version, "_") + ".bak"
	if err := os.Rename(exe, bak); err != nil {
		return fmt.Errorf("keeping the old binary as %s: %w", bak, err)
	}
	if err := os.Rename(tmp.Name(), exe); err != nil {
		if rerr := os.Rename(bak, exe); rerr != nil {
			return fmt.Errorf("installing the new binary failed (%v) and the old one is at %s (%v); move it back to %s", err, bak, rerr, exe)
		}
		return fmt.Errorf("installing the new binary: %w; the old one is back in place", err)
	}
	fmt.Printf("Upgraded keydrop %s → %s. The old binary is at %s.\n", version, newVersion, bak)
	return nil
}

var bakSafe = regexp.MustCompile(`[^A-Za-z0-9._-]`)

// sumFor finds name's hash in sha256sum output ("<hex>  name", or
// "<hex> *name" in binary mode).
func sumFor(sums, name string) string {
	sc := bufio.NewScanner(strings.NewReader(sums))
	for sc.Scan() {
		f := strings.Fields(sc.Text())
		if len(f) == 2 && strings.TrimPrefix(f[1], "*") == name && len(f[0]) == 64 {
			if _, err := hex.DecodeString(f[0]); err == nil {
				return strings.ToLower(f[0])
			}
		}
	}
	return ""
}
