package server

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// Fingerprint is the SHA-256 of a certificate's DER bytes, "sha256:<hex>".
// The CLI pins this (KEYDROP_TLS_PIN) when the server uses a self-signed
// certificate.
func Fingerprint(der []byte) string {
	h := sha256.Sum256(der)
	return "sha256:" + hex.EncodeToString(h[:])
}

// Sealer encrypts the TLS key at rest with the master key (the store).
type Sealer interface {
	SealBlob(name string, pt []byte) []byte
	OpenBlob(name string, ct []byte) ([]byte, error)
}

// sealedKeyType is the PEM type of a tls.key sealed with the master key. It
// ends in " PRIVATE KEY", so a release that predates sealing fails to parse
// it and refuses to start, rather than making a new certificate (which
// would change the pin every agent holds).
const sealedKeyType = "KEYDROP SEALED PRIVATE KEY"

// keyBlobName binds the sealed key to its role (the AAD).
const keyBlobName = "tls.key"

// ErrHalfPair: only one of tls.crt and tls.key is in the data directory.
var ErrHalfPair = errors.New("only one of tls.crt and tls.key is in the data directory, so the certificate can't be loaded; " +
	"refusing to make a new one, which would change the pin every agent holds. Restore the missing file from a backup. " +
	"If no agent has paired yet (or you mean to re-pin them all), remove the other file too and a new certificate is made on start")

// ErrKeyNotSealed: tls.key is in plaintext, as a release before sealing
// wrote it (or downgrade-data left it).
var ErrKeyNotSealed = errors.New("tls.key in the data directory isn't sealed with the master key (it's from an older release, or downgrade-data). " +
	"keydrop no longer seals it on start: stop keydrop and run `keydrop upgrade-data` once, then start it again")

// LoadOrCreateSelfSigned returns a certificate stored in dir, creating a
// 10-year ECDSA one on first run (when neither tls.crt nor tls.key exists;
// one without the other is ErrHalfPair). hosts become the SANs. The private
// key is stored sealed with the master key; a plaintext one is refused
// with ErrKeyNotSealed (SealTLSKey, run by upgrade-data, seals it).
func LoadOrCreateSelfSigned(dir string, hosts []string, sealer Sealer) (tls.Certificate, string, error) {
	c, sealed, err := loadPair(dir, sealer)
	switch {
	case errors.Is(err, os.ErrNotExist):
		return createSelfSigned(dir, hosts, sealer)
	case err != nil:
		return tls.Certificate{}, "", err
	case !sealed:
		return tls.Certificate{}, "", ErrKeyNotSealed
	}
	return c, Fingerprint(c.Certificate[0]), nil
}

// loadPair reads tls.crt and tls.key from dir. Neither there is
// os.ErrNotExist; just one is ErrHalfPair. sealed says how tls.key was
// stored.
func loadPair(dir string, sealer Sealer) (c tls.Certificate, sealed bool, err error) {
	certPath, keyPath := filepath.Join(dir, "tls.crt"), filepath.Join(dir, "tls.key")
	certPEM, err1 := os.ReadFile(certPath)
	keyFile, err2 := os.ReadFile(keyPath)
	switch {
	case err1 != nil && !errors.Is(err1, os.ErrNotExist):
		return c, false, err1
	case err2 != nil && !errors.Is(err2, os.ErrNotExist):
		return c, false, err2
	case err1 != nil && err2 != nil:
		return c, false, os.ErrNotExist
	case err1 != nil || err2 != nil:
		// Half a pair: making a new one would silently change the pin
		// every agent holds.
		return c, false, ErrHalfPair
	}
	keyPEM, sealed, err := openKey(keyFile, sealer)
	if err != nil {
		return c, false, err
	}
	c, err = tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return c, false, fmt.Errorf("%s and %s: %w", certPath, keyPath, err)
	}
	return c, sealed, nil
}

// SealTLSKey seals a plaintext tls.key in dir in place, keeping the same key
// and certificate (so the pin doesn't change). It returns the certificate's
// fingerprint ("" if dir has no certificate), and whether it sealed
// anything; an already sealed key is left alone.
func SealTLSKey(dir string, sealer Sealer) (fp string, sealed bool, err error) {
	c, already, err := loadPair(dir, sealer)
	if errors.Is(err, os.ErrNotExist) {
		return "", false, nil
	} else if err != nil {
		return "", false, err
	}
	fp = Fingerprint(c.Certificate[0])
	if already {
		return fp, false, nil
	}
	keyPath := filepath.Join(dir, "tls.key")
	keyPEM, err := os.ReadFile(keyPath)
	if err != nil {
		return "", false, err
	}
	if err := writeSealedKey(keyPath, keyPEM, sealer); err != nil {
		return "", false, fmt.Errorf("sealing %s: %w", keyPath, err)
	}
	return fp, true, nil
}

// RotateSelfSigned replaces the self-signed certificate in dir with a new
// key and certificate (sealed, as on first run). The old tls.crt and
// tls.key are kept beside them as tls.crt.<stamp>.bak and
// tls.key.<stamp>.bak (the key stays sealed as it was). It returns the new
// fingerprint and the backup paths.
func RotateSelfSigned(dir string, hosts []string, sealer Sealer, now time.Time) (string, []string, error) {
	if _, _, err := loadPair(dir, sealer); errors.Is(err, os.ErrNotExist) {
		return "", nil, errors.New("there's no tls.crt and tls.key in the data directory to rotate; keydrop makes them on its first start")
	} else if err != nil {
		return "", nil, err
	}
	stamp := now.UTC().Format("20060102T150405Z")
	names := []string{"tls.key", "tls.crt"}
	for _, name := range names { // check both first: never leave half a pair
		if _, err := os.Lstat(filepath.Join(dir, name+"."+stamp+".bak")); err == nil {
			return "", nil, fmt.Errorf("%s.%s.bak already exists; try again in a second", name, stamp)
		}
	}
	var backups []string
	for _, name := range names {
		to := filepath.Join(dir, name+"."+stamp+".bak")
		if err := os.Rename(filepath.Join(dir, name), to); err != nil {
			return "", backups, err
		}
		backups = append(backups, to)
	}
	_, fp, err := createSelfSigned(dir, hosts, sealer)
	if err != nil {
		return "", backups, fmt.Errorf("making the new certificate (the old one is in %s; rename them back to undo): %w", strings.Join(backups, " and "), err)
	}
	return fp, backups, nil
}

// createSelfSigned makes a new key and certificate in dir. The key is
// written (sealed) before the certificate.
func createSelfSigned(dir string, hosts []string, sealer Sealer) (tls.Certificate, string, error) {
	certPath, keyPath := filepath.Join(dir, "tls.crt"), filepath.Join(dir, "tls.key")
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, "", err
	}
	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 127))
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "keydrop"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().AddDate(10, 0, 0),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{"localhost"},
	}
	for _, h := range hosts {
		if ip := net.ParseIP(h); ip != nil {
			tmpl.IPAddresses = append(tmpl.IPAddresses, ip)
		} else if h != "" {
			tmpl.DNSNames = append(tmpl.DNSNames, h)
		}
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return tls.Certificate{}, "", err
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return tls.Certificate{}, "", err
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	if err := writeSealedKey(keyPath, keyPEM, sealer); err != nil {
		return tls.Certificate{}, "", err
	}
	if err := writeFileSync(certPath, certPEM, 0o644); err != nil {
		return tls.Certificate{}, "", err
	}
	c, err := tls.X509KeyPair(certPEM, keyPEM)
	return c, Fingerprint(der), err
}

// openKey returns the plaintext PEM of a tls.key file, and whether it was
// sealed.
func openKey(file []byte, sealer Sealer) ([]byte, bool, error) {
	b, _ := pem.Decode(file)
	if b == nil || b.Type != sealedKeyType {
		return file, false, nil
	}
	pt, err := sealer.OpenBlob(keyBlobName, b.Bytes)
	if err != nil {
		return nil, true, fmt.Errorf("tls.key: can't decrypt it with this master key: %w", err)
	}
	return pt, true, nil
}

// writeSealedKey writes keyPEM sealed to path, replacing it atomically. It
// checks that what's on disk decrypts back to keyPEM before the rename, so
// a plaintext key is only ever replaced by a readable sealed copy of
// itself.
func writeSealedKey(path string, keyPEM []byte, sealer Sealer) error {
	out := pem.EncodeToMemory(&pem.Block{Type: sealedKeyType, Bytes: sealer.SealBlob(keyBlobName, keyPEM)})
	return replaceFile(path, out, 0o600, func(written []byte) error {
		got, sealed, err := openKey(written, sealer)
		if err != nil || !sealed || !bytes.Equal(got, keyPEM) {
			return errors.New("sealed key didn't read back correctly")
		}
		return nil
	})
}

// UnsealTLSKey writes tls.key back as plaintext, for going back to a release
// that predates sealing. It does nothing if the key isn't sealed or there
// is none.
func UnsealTLSKey(dir string, sealer Sealer) (bool, error) {
	path := filepath.Join(dir, "tls.key")
	file, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	} else if err != nil {
		return false, err
	}
	keyPEM, sealed, err := openKey(file, sealer)
	if err != nil || !sealed {
		return false, err
	}
	return true, replaceFile(path, keyPEM, 0o600, func(written []byte) error {
		if !bytes.Equal(written, keyPEM) {
			return errors.New("key didn't read back correctly")
		}
		return nil
	})
}

// replaceFile writes data to a temp file beside path, syncs it, reads it
// back through check, and only then renames it over path.
func replaceFile(path string, data []byte, mode os.FileMode, check func([]byte) error) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), ".keydrop-*.tmp")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if err := tmp.Chmod(mode); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	written, err := os.ReadFile(tmp.Name())
	if err != nil {
		return err
	}
	if err := check(written); err != nil {
		return err
	}
	if err := os.Rename(tmp.Name(), path); err != nil {
		return err
	}
	if d, err := os.Open(filepath.Dir(path)); err == nil {
		d.Sync()
		d.Close()
	}
	return nil
}

func writeFileSync(path string, data []byte, mode os.FileMode) error {
	return replaceFile(path, data, mode, func([]byte) error { return nil })
}
