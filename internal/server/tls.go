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

// LoadOrCreateSelfSigned returns a certificate stored in dir, creating a
// 10-year ECDSA one on first run. hosts become the SANs. The private key is
// stored sealed with the master key; a plaintext tls.key from an earlier
// release is sealed in place, keeping the same key and certificate, and
// migrated reports that it was.
func LoadOrCreateSelfSigned(dir string, hosts []string, sealer Sealer) (c tls.Certificate, fp string, migrated bool, err error) {
	certPath, keyPath := filepath.Join(dir, "tls.crt"), filepath.Join(dir, "tls.key")
	certPEM, err1 := os.ReadFile(certPath)
	keyFile, err2 := os.ReadFile(keyPath)
	switch {
	case err1 == nil && err2 == nil:
		keyPEM, sealed, err := openKey(keyFile, sealer)
		if err != nil {
			return tls.Certificate{}, "", false, err
		}
		c, err := tls.X509KeyPair(certPEM, keyPEM)
		if err != nil {
			return tls.Certificate{}, "", false, fmt.Errorf("%s and %s: %w", certPath, keyPath, err)
		}
		if !sealed {
			if err := writeSealedKey(keyPath, keyPEM, sealer); err != nil {
				return tls.Certificate{}, "", false, fmt.Errorf("sealing %s: %w", keyPath, err)
			}
			migrated = true
		}
		return c, Fingerprint(c.Certificate[0]), migrated, nil
	case err1 != nil && !errors.Is(err1, os.ErrNotExist):
		return tls.Certificate{}, "", false, err1
	case err2 != nil && !errors.Is(err2, os.ErrNotExist):
		return tls.Certificate{}, "", false, err2
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, "", false, err
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
		return tls.Certificate{}, "", false, err
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return tls.Certificate{}, "", false, err
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	if err := writeSealedKey(keyPath, keyPEM, sealer); err != nil {
		return tls.Certificate{}, "", false, err
	}
	if err := writeFileSync(certPath, certPEM, 0o644); err != nil {
		return tls.Certificate{}, "", false, err
	}
	c, err = tls.X509KeyPair(certPEM, keyPEM)
	return c, Fingerprint(der), false, err
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
