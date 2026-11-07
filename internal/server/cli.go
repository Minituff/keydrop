package server

import (
	"compress/gzip"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"text/template"
	"time"
)

// The server hands out the CLI it was built with, so an agent machine
// needs nothing but curl and the server's address: no GitHub access, and
// the CLI's version always matches the server's.

// cliFile matches the gzipped builds the Docker image puts in
// KEYDROP_CLI_DIR. They're served decompressed, under the name without .gz.
var cliFile = regexp.MustCompile(`^keydrop-(linux|darwin|windows)-(amd64|arm64)(\.exe)?\.gz$`)

// CLIBuild is one downloadable CLI.
type CLIBuild struct {
	Name string // keydrop-linux-arm64
	OS   string
	Arch string
	Size int64 // decompressed
	path string
}

// LoadCLI lists the CLI builds in dir. A missing dir means none.
func LoadCLI(dir string) ([]CLIBuild, error) {
	if dir == "" {
		return nil, nil
	}
	ents, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	var out []CLIBuild
	for _, e := range ents {
		m := cliFile.FindStringSubmatch(e.Name())
		if m == nil {
			continue
		}
		p := filepath.Join(dir, e.Name())
		size, err := gzipSize(p)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", p, err)
		}
		out = append(out, CLIBuild{Name: strings.TrimSuffix(e.Name(), ".gz"), OS: m[1], Arch: m[2], Size: size, path: p})
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("no keydrop-<os>-<arch>.gz builds in %s", dir)
	}
	if _, err := os.Stat(filepath.Join(dir, "SHA256SUMS")); err != nil {
		return nil, err
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

// gzipSize reads the decompressed size from a gzip trailer, so downloads
// carry a Content-Length and curl notices a cut-off transfer.
func gzipSize(path string) (int64, error) {
	f, err := os.Open(path)
	if err != nil {
		return 0, err
	}
	defer f.Close()
	var b [4]byte
	if _, err := f.Seek(-4, io.SeekEnd); err != nil {
		return 0, err
	}
	if _, err := io.ReadFull(f, b[:]); err != nil {
		return 0, err
	}
	return int64(binary.LittleEndian.Uint32(b[:])), nil
}

// KeyPin is curl's --pinnedpubkey form of a certificate's public key,
// "sha256//<base64>". The certificate pin (Fingerprint) is what the CLI
// checks; curl can only pin the key.
func KeyPin(der []byte) (string, error) {
	c, err := x509.ParseCertificate(der)
	if err != nil {
		return "", err
	}
	h := sha256.Sum256(c.RawSubjectPublicKeyInfo)
	return "sha256//" + base64.StdEncoding.EncodeToString(h[:]), nil
}

// downloads caps concurrent CLI downloads: they're unauthenticated and
// each is several megabytes. Each address (IPv6: /64) gets at most
// downloadsPerAddr of the slots, and a reader that stalls for
// downloadIdle is cut off, so a few slow clients can't hold them all.
var downloads = make(chan struct{}, 8)

const (
	downloadsPerAddr = 2
	downloadIdle     = 30 * time.Second
	downloadMax      = 10 * time.Minute
)

var (
	downloadsMu     sync.Mutex
	downloadsByAddr = map[string]int{}
)

// deadlineWriter pushes the write deadline forward before each write, so
// a stalled reader times out after downloadIdle, and none lasts past end.
type deadlineWriter struct {
	w   http.ResponseWriter
	rc  *http.ResponseController
	end time.Time
}

func (d deadlineWriter) Write(p []byte) (int, error) {
	dl := time.Now().Add(downloadIdle)
	if dl.After(d.end) {
		dl = d.end
	}
	d.rc.SetWriteDeadline(dl)
	return d.w.Write(p)
}

func (s *Server) cliBuild(name string) (CLIBuild, bool) {
	for _, b := range s.cfg.CLI {
		if b.Name == name {
			return b, true
		}
	}
	return CLIBuild{}, false
}

func (s *Server) handleCLI(w http.ResponseWriter, r *http.Request) {
	if len(s.cfg.CLI) == 0 {
		http.Error(w, "this server has no CLI builds to hand out (KEYDROP_CLI_DIR isn't set)", http.StatusNotFound)
		return
	}
	name := r.PathValue("file")
	if name == "SHA256SUMS" {
		http.ServeFile(w, r, filepath.Join(filepath.Dir(s.cfg.CLI[0].path), "SHA256SUMS"))
		return
	}
	b, ok := s.cliBuild(name)
	if !ok {
		http.Error(w, "no such build; see /install.sh or the Agents page", http.StatusNotFound)
		return
	}
	addr := sourceGroup(s.clientIP(r))
	downloadsMu.Lock()
	if downloadsByAddr[addr] >= downloadsPerAddr {
		downloadsMu.Unlock()
		w.Header().Set("Retry-After", "10")
		http.Error(w, "too many downloads from this address at once, try again shortly", http.StatusServiceUnavailable)
		return
	}
	downloadsByAddr[addr]++
	downloadsMu.Unlock()
	defer func() {
		downloadsMu.Lock()
		if downloadsByAddr[addr]--; downloadsByAddr[addr] <= 0 {
			delete(downloadsByAddr, addr)
		}
		downloadsMu.Unlock()
	}()
	select {
	case downloads <- struct{}{}:
		defer func() { <-downloads }()
	default:
		w.Header().Set("Retry-After", "10")
		http.Error(w, "too many downloads at once, try again shortly", http.StatusServiceUnavailable)
		return
	}
	f, err := os.Open(b.path)
	if err != nil {
		http.Error(w, "build unavailable", http.StatusInternalServerError)
		return
	}
	defer f.Close()
	zr, err := gzip.NewReader(f)
	if err != nil {
		http.Error(w, "build unavailable", http.StatusInternalServerError)
		return
	}
	// The server's write timeout suits API calls, not a slow link: allow
	// up to downloadMax in all, but no stall longer than downloadIdle.
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Disposition", `attachment; filename="`+b.Name+`"`)
	w.Header().Set("Content-Length", strconv.FormatInt(b.Size, 10))
	io.CopyBuffer(deadlineWriter{w, http.NewResponseController(w), time.Now().Add(downloadMax)}, zr, make([]byte, 32<<10))
}

// safeHost is what can go into a shell script unquoted-safe: a hostname or
// IP with an optional port.
var safeHost = regexp.MustCompile(`^[A-Za-z0-9.\-]+(:[0-9]+)?$|^\[[0-9A-Fa-f:.]+\](:[0-9]+)?$`)

// installTarget is where install.sh downloads from: the URL the script was
// fetched from. Directly from keydrop's own self-signed certificate it
// pins the key; through a proxy it uses the public URL and normal
// certificate checks.
//
// It never hands out a script that downloads over plain HTTP, including
// when a trusted proxy reports (X-Forwarded-Proto) that the client used
// http: errMsg says why instead.
//
// /setup.md follows the same rules (what names it in the messages).
func (s *Server) installTarget(r *http.Request, what string) (base, keyPin, certPin, errMsg string) {
	if s.viaProxy(r) {
		// The proxy must say the client's hop was https; otherwise this is
		// the same plain-http fetch refused below.
		if !strings.EqualFold(strings.TrimSpace(r.Header.Get("X-Forwarded-Proto")), "https") {
			return "", "", "", what + " is only offered over https (the proxy didn't send X-Forwarded-Proto: https); fetch it with https"
		}
		pub := strings.TrimRight(s.cfg.PublicURL, "/")
		if !strings.HasPrefix(pub, "https://") || s.cfg.PublicURLGuess {
			return "", "", "", "set KEYDROP_PUBLIC_URL to the proxy's https:// address to fetch " + what + " through it"
		}
		return pub, "", "", ""
	}
	if !safeHost.MatchString(r.Host) {
		return "", "", "", "unexpected Host header"
	}
	if r.TLS == nil {
		return "", "", "", what + " is only offered over https (over http, nothing would check it came from keydrop); fetch it with https"
	}
	return "https://" + r.Host, s.cfg.KeyPin, s.cfg.CertPin, ""
}

// viaProxy reports whether the request came from a trusted proxy.
func (s *Server) viaProxy(r *http.Request) bool {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	a, err := netip.ParseAddr(host)
	return err == nil && s.trusted(a)
}

var installScript = template.Must(template.New("install").Parse(`#!/bin/sh
# Installs the keydrop CLI from the keydrop server that served this script
# (keydrop {{.Version}}). Linux and macOS, amd64 and arm64.
# KEYDROP_INSTALL_DIR overrides where it goes (default ~/.local/bin).
set -eu
base='{{.Base}}'
pin='{{.KeyPin}}'
dir="${KEYDROP_INSTALL_DIR:-$HOME/.local/bin}"

case "$(uname -s)" in
  Linux) os=linux ;;
  Darwin) os=darwin ;;
  *) echo "keydrop: no installer for $(uname -s); download a build from the Agents page" >&2; exit 1 ;;
esac
case "$(uname -m)" in
  x86_64|amd64) arch=amd64 ;;
  aarch64|arm64) arch=arm64 ;;
  *) echo "keydrop: no build for $(uname -m)" >&2; exit 1 ;;
esac
name="keydrop-$os-$arch"

fetch() {
  if [ -n "$pin" ]; then
    # -k skips the CA check; --pinnedpubkey replaces it with this server's key.
    curl -fsSk --proto =https --pinnedpubkey "$pin" -o "$2" "$base/cli/$1"
  else
    curl -fsS --proto =https -o "$2" "$base/cli/$1"
  fi
}

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
fetch "$name" "$tmp/keydrop"
fetch SHA256SUMS "$tmp/SHA256SUMS"
want=$(awk -v n="$name" '$2 == n || $2 == "*" n { print $1 }' "$tmp/SHA256SUMS")
if command -v sha256sum >/dev/null 2>&1; then
  got=$(sha256sum "$tmp/keydrop" | awk '{ print $1 }')
else
  got=$(shasum -a 256 "$tmp/keydrop" | awk '{ print $1 }')
fi
if [ -z "$want" ] || [ "$want" != "$got" ]; then
  echo "keydrop: the download doesn't match its checksum; nothing installed" >&2
  exit 1
fi
chmod 755 "$tmp/keydrop"
mkdir -p "$dir"
mv "$tmp/keydrop" "$dir/keydrop"
echo "Installed $("$dir/keydrop" --version) to $dir/keydrop"
case ":$PATH:" in
  *":$dir:"*) ;;
  *) echo "Add $dir to your PATH." ;;
esac
echo "Next: keydrop pair --url $base{{if .CertPin}} --pin {{.CertPin}}{{end}}"
`))

func (s *Server) handleInstallScript(w http.ResponseWriter, r *http.Request) {
	if len(s.cfg.CLI) == 0 {
		http.Error(w, "this server has no CLI builds to hand out (KEYDROP_CLI_DIR isn't set)", http.StatusNotFound)
		return
	}
	base, keyPin, certPin, errMsg := s.installTarget(r, "install.sh")
	if errMsg != "" {
		http.Error(w, errMsg, http.StatusBadRequest)
		return
	}
	w.Header().Set("Content-Type", "text/x-shellscript; charset=utf-8")
	installScript.Execute(w, map[string]string{"Version": s.cfg.Version, "Base": base, "KeyPin": keyPin, "CertPin": certPin})
}

// InstallCommands are the one-liners shown on the Agents page and in the
// log. public goes through the public URL when that's a proxy with a real
// certificate; direct goes straight to keydrop with its key pinned.
func (c Config) InstallCommands() (public, direct string) {
	if len(c.CLI) == 0 {
		return "", ""
	}
	public, direct = c.fetchCommands("/install.sh")
	if public != "" {
		public += " | sh"
	}
	if direct != "" {
		direct += " | sh"
	}
	return public, direct
}
