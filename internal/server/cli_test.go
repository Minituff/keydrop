package server

import (
	"bytes"
	"compress/gzip"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/minituff/keydrop/internal/store"
)

// fakeCLIDir writes gzipped stand-in builds and a SHA256SUMS, like the
// Docker image's /cli.
func fakeCLIDir(t *testing.T) (string, map[string][]byte) {
	t.Helper()
	dir := t.TempDir()
	builds := map[string][]byte{
		"keydrop-linux-amd64":       []byte("fake linux amd64 build"),
		"keydrop-linux-arm64":       []byte("fake linux arm64 build, a bit longer"),
		"keydrop-windows-amd64.exe": []byte("fake windows build"),
	}
	var sums strings.Builder
	for name, body := range builds {
		var buf bytes.Buffer
		zw := gzip.NewWriter(&buf)
		zw.Write(body)
		zw.Close()
		os.WriteFile(filepath.Join(dir, name+".gz"), buf.Bytes(), 0o644)
		h := sha256.Sum256(body)
		sums.WriteString(hex.EncodeToString(h[:]) + "  " + name + "\n")
	}
	os.WriteFile(filepath.Join(dir, "SHA256SUMS"), []byte(sums.String()), 0o644)
	os.WriteFile(filepath.Join(dir, "README"), []byte("not a build"), 0o644)
	return dir, builds
}

func fetch(t *testing.T, c *http.Client, url string, hdr ...string) (int, http.Header, string) {
	t.Helper()
	req, _ := http.NewRequest("GET", url, nil)
	for i := 0; i+1 < len(hdr); i += 2 {
		req.Header.Set(hdr[i], hdr[i+1])
	}
	resp, err := c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, resp.Header, string(b)
}

func TestCLIDownloads(t *testing.T) {
	h := newHarness(t)
	if code, _ := h.get("/install.sh"); code != http.StatusNotFound {
		t.Fatalf("install.sh without builds: %d", code)
	}
	if code, _ := h.get("/cli/keydrop-linux-amd64"); code != http.StatusNotFound {
		t.Fatalf("download without builds: %d", code)
	}

	dir, builds := fakeCLIDir(t)
	cli, err := LoadCLI(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(cli) != 3 || cli[0].Name != "keydrop-linux-amd64" || cli[2].OS != "windows" {
		t.Fatalf("LoadCLI = %+v", cli)
	}
	h.srv.cfg.CLI = cli
	h.srv.cfg.Version = "v9.9.9"

	for name, body := range builds {
		code, hdr, got := fetch(t, http.DefaultClient, h.ts.URL+"/cli/"+name)
		if code != http.StatusOK || got != string(body) {
			t.Fatalf("%s: %d %q", name, code, got)
		}
		if hdr.Get("Content-Length") != strconv.Itoa(len(body)) {
			t.Errorf("%s: Content-Length %s, want %d", name, hdr.Get("Content-Length"), len(body))
		}
	}
	if code, body := h.get("/cli/SHA256SUMS"); code != http.StatusOK || !strings.Contains(body, "  keydrop-linux-arm64\n") {
		t.Fatalf("SHA256SUMS: %d %s", code, body)
	}
	for _, bad := range []string{"keydrop-linux-amd64.gz", "README", "..%2fSHA256SUMS", "keydrop-plan9-amd64"} {
		if code, _ := h.get("/cli/" + bad); code != http.StatusNotFound {
			t.Errorf("/cli/%s: %d, want 404", bad, code)
		}
	}

	// Plain HTTP straight to keydrop: refused, never an unpinned download.
	code, _, script := fetch(t, http.DefaultClient, h.ts.URL+"/install.sh")
	if code != http.StatusBadRequest || strings.Contains(script, "curl") {
		t.Fatalf("install.sh over http: %d\n%s", code, script)
	}
	// A Host header that could break out of the script's quotes is refused.
	for _, host := range []string{"x';rm -rf ~;'", "a b", "$(id)", "[::1]:8443x"} {
		r := httptest.NewRequest("GET", "/install.sh", nil)
		r.Host = host
		w := httptest.NewRecorder()
		h.srv.ServeHTTP(w, r)
		if w.Code != http.StatusBadRequest {
			t.Errorf("Host %q: %d", host, w.Code)
		}
	}
	// Through a trusted proxy: the public URL, normal certificate checks.
	h.srv.cfg.PublicURL = "https://secrets.example.com"
	h.srv.cfg.KeyPin, h.srv.cfg.CertPin = "sha256//KEYPIN=", "sha256:certpin"
	h.srv.cfg.TrustedProxies = []netip.Prefix{netip.MustParsePrefix("127.0.0.1/32"), netip.MustParsePrefix("::1/128")}
	_, _, script = fetch(t, http.DefaultClient, h.ts.URL+"/install.sh", "X-Forwarded-For", "10.0.0.5")
	if !strings.Contains(script, "base='https://secrets.example.com'") || !strings.Contains(script, "pin=''") || strings.Contains(script, "--pin sha256") ||
		!strings.Contains(script, "--proto =https") {
		t.Fatalf("install.sh via proxy:\n%s", script)
	}
	// A proxy with an http public URL would mean an unverified download.
	h.srv.cfg.PublicURL = "http://secrets.example.com"
	if code, _, _ := fetch(t, http.DefaultClient, h.ts.URL+"/install.sh", "X-Forwarded-For", "10.0.0.5"); code != http.StatusBadRequest {
		t.Fatalf("install.sh via an http proxy URL: %d", code)
	}
	h.srv.cfg.PublicURL = "https://secrets.example.com"
	h.srv.cfg.TrustedProxies = nil

	// The Agents page shows the install commands and download links.
	h.srv.cfg.DirectURL = "https://10.0.0.5:8443"
	h.setup()
	if _, body := h.get("/tokens"); !strings.Contains(body, "--pinnedpubkey &#39;sha256//KEYPIN=&#39; https://10.0.0.5:8443/install.sh") ||
		!strings.Contains(body, `href="/cli/keydrop-linux-arm64"`) || !strings.Contains(body, "--pin sha256:certpin") || !strings.Contains(body, "keydrop v9.9.9") {
		t.Fatalf("Agents page:\n%s", body)
	}

	// Over keydrop's own TLS: the key pin goes into the script, the
	// certificate pin into the pairing hint.
	ts := httptest.NewTLSServer(h.srv)
	defer ts.Close()
	_, _, script = fetch(t, ts.Client(), ts.URL+"/install.sh")
	if !strings.Contains(script, "base='"+ts.URL+"'") || !strings.Contains(script, "pin='sha256//KEYPIN='") ||
		!strings.Contains(script, "keydrop pair --url $base --pin sha256:certpin") {
		t.Fatalf("install.sh over TLS:\n%s", script)
	}
}

func testSealer(t *testing.T, dir string) *store.Store {
	st, err := store.Open(dir, bytes.Repeat([]byte{7}, 32))
	if err != nil {
		t.Fatal(err)
	}
	return st
}

func TestKeyPin(t *testing.T) {
	dir := t.TempDir()
	st := testSealer(t, dir)
	c, _, _, err := LoadOrCreateSelfSigned(dir, []string{"10.0.0.5"}, st)
	if err != nil {
		t.Fatal(err)
	}
	pin, err := KeyPin(c.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	h := sha256.Sum256(c.Leaf.RawSubjectPublicKeyInfo)
	if want := "sha256//" + base64.StdEncoding.EncodeToString(h[:]); pin != want {
		t.Fatalf("KeyPin = %s, want %s", pin, want)
	}
	// The key is stored, so the pin survives a restart.
	c2, _, _, err := LoadOrCreateSelfSigned(dir, nil, st)
	if err != nil {
		t.Fatal(err)
	}
	if pin2, _ := KeyPin(c2.Certificate[0]); pin2 != pin {
		t.Fatalf("pin changed on reload: %s → %s", pin, pin2)
	}
	// It's stored sealed, never as a plaintext key.
	raw, _ := os.ReadFile(filepath.Join(dir, "tls.key"))
	if strings.Contains(string(raw), "EC PRIVATE KEY") || !strings.Contains(string(raw), sealedKeyType) {
		t.Fatalf("tls.key isn't sealed:\n%s", raw)
	}
	// Another master key can't open it, and nothing is regenerated.
	other, _ := store.Open(t.TempDir(), bytes.Repeat([]byte{8}, 32))
	if _, _, _, err := LoadOrCreateSelfSigned(dir, nil, other); err == nil {
		t.Fatal("opened with the wrong master key")
	}
	if raw2, _ := os.ReadFile(filepath.Join(dir, "tls.key")); !bytes.Equal(raw, raw2) {
		t.Fatal("tls.key changed after a failed open")
	}
}

// A plaintext tls.key from an earlier release is sealed in place, and the
// certificate (and so every agent's pin) stays the same. Unsealing gives
// the original back for a downgrade.
func TestTLSKeyMigration(t *testing.T) {
	dir := t.TempDir()
	st := testSealer(t, dir)
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), NotBefore: time.Now(), NotAfter: time.Now().Add(time.Hour)}
	der, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	keyDER, _ := x509.MarshalECPrivateKey(key)
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	os.WriteFile(filepath.Join(dir, "tls.key"), keyPEM, 0o600)
	os.WriteFile(filepath.Join(dir, "tls.crt"), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o644)

	c, fp, migrated, err := LoadOrCreateSelfSigned(dir, nil, st)
	if err != nil || !migrated {
		t.Fatalf("migrate: %v %v", migrated, err)
	}
	if fp != Fingerprint(der) || !bytes.Equal(c.Certificate[0], der) {
		t.Fatal("certificate changed during migration")
	}
	raw, _ := os.ReadFile(filepath.Join(dir, "tls.key"))
	if bytes.Contains(raw, keyPEM) || !bytes.Contains(raw, []byte(sealedKeyType)) {
		t.Fatal("plaintext key left behind")
	}
	if _, fp2, migrated, err := LoadOrCreateSelfSigned(dir, nil, st); err != nil || migrated || fp2 != fp {
		t.Fatalf("second start: %v %v %s", migrated, err, fp2)
	}
	// A release that predates sealing can't parse it, so it refuses to start
	// rather than making a new certificate.
	if _, err := tls.LoadX509KeyPair(filepath.Join(dir, "tls.crt"), filepath.Join(dir, "tls.key")); err == nil || errors.Is(err, os.ErrNotExist) {
		t.Fatalf("old loader: %v", err)
	}
	if ok, err := UnsealTLSKey(dir, st); !ok || err != nil {
		t.Fatalf("unseal: %v %v", ok, err)
	}
	if raw, _ := os.ReadFile(filepath.Join(dir, "tls.key")); !bytes.Equal(raw, keyPEM) {
		t.Fatal("unsealed key differs from the original")
	}
}

func TestInstallCommands(t *testing.T) {
	cli := []CLIBuild{{Name: "keydrop-linux-amd64"}}
	for _, tc := range []struct {
		cfg            Config
		public, direct string
	}{
		{Config{}, "", ""},
		// Behind a proxy with its own certificate: both.
		{Config{CLI: cli, PublicURL: "https://secrets.example.com", KeyPin: "sha256//K=", DirectURL: "https://10.0.0.5:8443",
			TrustedProxies: []netip.Prefix{netip.MustParsePrefix("10.0.0.2/32")}},
			"curl -fsS https://secrets.example.com/install.sh | sh",
			"curl -fsSk --pinnedpubkey 'sha256//K=' https://10.0.0.5:8443/install.sh | sh"},
		// Self-signed with no proxy: the public URL is keydrop itself, so only the pinned one.
		{Config{CLI: cli, PublicURL: "https://10.0.0.5:8443", KeyPin: "sha256//K=", DirectURL: "https://10.0.0.5:8443"},
			"", "curl -fsSk --pinnedpubkey 'sha256//K=' https://10.0.0.5:8443/install.sh | sh"},
		// TLS off behind a proxy: only the public one.
		{Config{CLI: cli, PublicURL: "https://secrets.example.com"}, "curl -fsS https://secrets.example.com/install.sh | sh", ""},
		// A guessed public URL isn't offered.
		{Config{CLI: cli, PublicURL: "https://localhost:8443", PublicURLGuess: true}, "", ""},
	} {
		p, d := tc.cfg.InstallCommands()
		if p != tc.public || d != tc.direct {
			t.Errorf("%+v:\n got %q %q\nwant %q %q", tc.cfg, p, d, tc.public, tc.direct)
		}
	}
}

func TestVersionHeader(t *testing.T) {
	h := newHarness(t)
	h.srv.cfg.Version = "v9.9.9"
	tok, err := h.st.CreateToken("box", []string{"lab"}, false, nil)
	if err != nil {
		t.Fatal(err)
	}
	req, _ := http.NewRequest("GET", h.ts.URL+"/api/v1/whoami", nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.Header.Get("X-Keydrop-Version") != "v9.9.9" {
		t.Fatalf("authenticated: version header %q", resp.Header.Get("X-Keydrop-Version"))
	}
	for _, path := range []string{"/api/v1/whoami", "/healthz", "/login"} {
		resp, err := http.Get(h.ts.URL + path)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if v := resp.Header.Get("X-Keydrop-Version"); v != "" {
			t.Errorf("%s without a token shows the version %q", path, v)
		}
	}
}

// One address can't take every download slot.
func TestDownloadSlotsPerAddress(t *testing.T) {
	h := newHarness(t)
	dir, _ := fakeCLIDir(t)
	cli, err := LoadCLI(dir)
	if err != nil {
		t.Fatal(err)
	}
	h.srv.cfg.CLI = cli
	downloadsMu.Lock()
	downloadsByAddr["127.0.0.1"] = downloadsPerAddr // two slow downloads in progress
	downloadsMu.Unlock()
	t.Cleanup(func() {
		downloadsMu.Lock()
		delete(downloadsByAddr, "127.0.0.1")
		downloadsMu.Unlock()
	})
	if code, _ := h.get("/cli/keydrop-linux-amd64"); code != http.StatusServiceUnavailable {
		t.Fatalf("third download from one address: %d", code)
	}
	downloadsMu.Lock()
	downloadsByAddr["127.0.0.1"] = 0
	downloadsMu.Unlock()
	if code, _ := h.get("/cli/keydrop-linux-amd64"); code != http.StatusOK {
		t.Fatalf("download: %d", code)
	}
}

// A huge ?days= can't overflow into "nothing expires".
func TestExpiringDaysBounded(t *testing.T) {
	h := newHarness(t)
	h.setup()
	tok, _ := h.st.CreateToken("agent", []string{"lab"}, false, nil)
	exp := time.Now().Add(400 * 24 * time.Hour)
	h.st.PutValue("lab", "SOON", []byte("expiring-value"), &store.Meta{Expires: &exp})
	_, _, body := h.api("GET", "/api/v1/expiring?days=9999999999999", tok, nil)
	if !strings.Contains(string(body), "lab/SOON") {
		t.Fatalf("huge days lost the secret: %s", body)
	}
}
