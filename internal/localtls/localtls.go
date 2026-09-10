// Package localtls owns a per-installation CA and renewable localhost certificate.
// No private material is included in the image or exported by the CLI.
package localtls

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/gofrs/flock"
)

const (
	leafLifetime = 90 * 24 * time.Hour
	renewBefore  = 30 * 24 * time.Hour
	stateName    = "identity.json"
)

var localLabel = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$`)

// CoversHost matches exactly the names covered by the managed certificate.
func CoversHost(host string) bool {
	host = strings.ToLower(host)
	if host == "localhost" || host == "127.0.0.1" || host == "::1" {
		return true
	}
	return strings.HasSuffix(host, ".localhost") && localLabel.MatchString(strings.TrimSuffix(host, ".localhost"))
}

type identity struct {
	CA          string `json:"ca"`
	CAKey       string `json:"ca_key"`
	Certificate string `json:"certificate"`
	Key         string `json:"key"`
}

// Status contains public certificate metadata only.
type Status struct {
	CAFingerprint      string    `json:"ca_sha256"`
	CAExpires          time.Time `json:"ca_expires"`
	CertificateExpires time.Time `json:"certificate_expires"`
	DNSNames           []string  `json:"dns_names"`
	RenewalDue         bool      `json:"renewal_due"`
}

type Manager struct {
	mu          sync.Mutex
	dir         string
	now         func() time.Time
	certificate *tls.Certificate
	ca          *x509.Certificate
	nextCheck   time.Time
	hosts       []string
}

func Open(dir string, hosts ...string) (*Manager, error) {
	m := &Manager{dir: dir, now: time.Now, hosts: append([]string{"manager.localhost", "primary.localhost"}, hosts...)}
	for _, host := range m.hosts {
		if !CoversHost(host) {
			return nil, fmt.Errorf("unsupported local certificate name %q", host)
		}
	}
	if err := m.refresh(); err != nil {
		return nil, err
	}
	return m, nil
}

// EnsureHosts explicitly lists configured DNS names, because some clients
// reject a wildcard directly below localhost. Retain previous SANs on renewal.
func (m *Manager) EnsureHosts(hosts []string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, host := range hosts {
		if !CoversHost(host) {
			return fmt.Errorf("unsupported local certificate name %q", host)
		}
		if !slices.Contains(m.hosts, host) {
			m.hosts = append(m.hosts, host)
		}
	}
	return m.refresh()
}

// GetCertificate renews before serving a handshake, including after long idle
// periods. It never changes the CA automatically, so existing host trust survives.
func (m *Manager) GetCertificate(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if hello != nil && hello.ServerName != "" && !CoversHost(hello.ServerName) {
		return nil, errors.New("local TLS only serves localhost names")
	}
	now := m.now()
	if !now.Before(m.nextCheck) || now.Before(m.certificate.Leaf.NotBefore) {
		if err := m.refresh(); err != nil {
			return nil, err
		}
	}
	if now.Before(m.ca.NotBefore) || !now.Before(m.ca.NotAfter) || !now.Before(m.certificate.Leaf.NotAfter) {
		return nil, errors.New("local TLS certificate expired or system clock is incorrect")
	}
	return m.certificate, nil
}

func (m *Manager) refresh() error {
	if err := os.MkdirAll(m.dir, 0o700); err != nil {
		return err
	}
	if err := os.Chmod(m.dir, 0o700); err != nil {
		return err
	}
	lock := flock.New(filepath.Join(m.dir, ".lock"))
	defer lock.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	locked, err := lock.TryLockContext(ctx, 25*time.Millisecond)
	if err != nil {
		return fmt.Errorf("lock local TLS state: %w", err)
	}
	if !locked {
		return errors.New("local TLS state is busy")
	}

	now := m.now()
	state, err := readIdentity(m.dir)
	changed := false
	if errors.Is(err, os.ErrNotExist) {
		// A surviving public CA indicates lost private state. Never silently
		// replace an identity the user may already trust.
		if _, statErr := os.Stat(filepath.Join(m.dir, "ca.crt")); !errors.Is(statErr, os.ErrNotExist) {
			return errors.New("local TLS identity is missing but ca.crt exists; restore the TLS backup or explicitly reset and trust a new CA")
		}
		state, err = newIdentity(now)
		changed = true
	}
	if err != nil {
		return fmt.Errorf("load local TLS identity (restore backup if damaged): %w", err)
	}
	caPair, err := tls.X509KeyPair([]byte(state.CA), []byte(state.CAKey))
	if err != nil {
		return fmt.Errorf("invalid local CA key pair: %w", err)
	}
	ca := caPair.Leaf
	if !ca.IsCA || ca.CheckSignatureFrom(ca) != nil {
		return errors.New("invalid local CA certificate")
	}
	if now.Before(ca.NotBefore) || !now.Before(ca.NotAfter) {
		return errors.New("local CA expired or not yet valid; check clock, or explicitly reset local TLS and trust the new CA")
	}
	if m.ca != nil && !m.ca.Equal(ca) {
		return errors.New("local CA changed on disk; restart the manager and trust the new CA")
	}
	var certificate tls.Certificate
	if state.Certificate != "" || state.Key != "" {
		certificate, err = tls.X509KeyPair([]byte(state.Certificate), []byte(state.Key))
		if err != nil {
			return fmt.Errorf("invalid local server key pair: %w", err)
		}
		if err := certificate.Leaf.CheckSignatureFrom(ca); err != nil {
			return fmt.Errorf("invalid local certificate issuer: %w", err)
		}
		for _, host := range []string{"localhost", "manager.localhost", "primary.localhost", "127.0.0.1", "::1"} {
			if err := certificate.Leaf.VerifyHostname(host); err != nil {
				return err
			}
		}
	}
	names := []string{"localhost", "*.localhost"}
	if certificate.Leaf != nil {
		names = append(names, certificate.Leaf.DNSNames...)
	}
	missingName := false
	for _, host := range m.hosts {
		if net.ParseIP(host) == nil && !slices.Contains(names, host) {
			names = append(names, host)
			missingName = true
		}
	}
	slices.Sort(names)
	names = slices.Compact(names)
	if missingName || certificate.Leaf == nil || !now.Add(renewBefore).Before(certificate.Leaf.NotAfter) || now.Before(certificate.Leaf.NotBefore) {
		if !now.Add(leafLifetime).Before(ca.NotAfter) {
			return errors.New("local CA is nearing expiry; explicitly reset local TLS and trust the new CA")
		}
		state.Certificate, state.Key, err = issueCertificate(now, ca, caPair.PrivateKey, names)
		if err != nil {
			return err
		}
		certificate, err = tls.X509KeyPair([]byte(state.Certificate), []byte(state.Key))
		if err != nil {
			return err
		}
		changed = true
	}
	if changed {
		data, err := json.MarshalIndent(state, "", "  ")
		if err != nil {
			return err
		}
		if err := writeAtomic(filepath.Join(m.dir, stateName), data); err != nil {
			return err
		}
	} else if err := os.Chmod(filepath.Join(m.dir, stateName), 0o600); err != nil {
		return err
	}
	// Export only the public CA. Repair this derived file from the identity.
	public, err := os.ReadFile(filepath.Join(m.dir, "ca.crt"))
	if err != nil || string(public) != state.CA {
		if err := writeAtomic(filepath.Join(m.dir, "ca.crt"), []byte(state.CA)); err != nil {
			return err
		}
	}
	m.certificate, m.ca = &certificate, ca
	m.nextCheck = now.Add(time.Hour)
	return nil
}

func readIdentity(dir string) (identity, error) {
	var state identity
	data, err := os.ReadFile(filepath.Join(dir, stateName))
	if err != nil {
		return state, err
	}
	if err := json.Unmarshal(data, &state); err != nil {
		return state, errors.New("invalid identity JSON")
	}
	return state, nil
}

// Inspect is read-only and works while the service is stopped. No auth config,
// Gateway process, or CA private key is exposed to callers.
func Inspect(dir string) (Status, []byte, error) {
	state, err := readIdentity(dir)
	if err != nil {
		return Status{}, nil, err
	}
	ca, err := parseCertificate(state.CA)
	if err != nil {
		return Status{}, nil, err
	}
	leaf, err := parseCertificate(state.Certificate)
	if err != nil {
		return Status{}, nil, err
	}
	if !ca.IsCA || ca.CheckSignatureFrom(ca) != nil || leaf.CheckSignatureFrom(ca) != nil {
		return Status{}, nil, errors.New("invalid local TLS certificate chain")
	}
	fingerprint := sha256.Sum256(ca.Raw)
	return Status{CAFingerprint: hex.EncodeToString(fingerprint[:]), CAExpires: ca.NotAfter,
			CertificateExpires: leaf.NotAfter, DNSNames: leaf.DNSNames,
			RenewalDue: !time.Now().Add(renewBefore).Before(leaf.NotAfter)},
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ca.Raw}), nil
}

func parseCertificate(value string) (*x509.Certificate, error) {
	block, _ := pem.Decode([]byte(value))
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, errors.New("invalid certificate PEM")
	}
	return x509.ParseCertificate(block.Bytes)
}

func newIdentity(now time.Time) (identity, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return identity{}, err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return identity{}, err
	}
	serial.Add(serial, big.NewInt(1))
	template := &x509.Certificate{SerialNumber: serial,
		Subject:   pkix.Name{CommonName: "IBKR Gateway Local CA " + serial.Text(16)},
		NotBefore: now.Add(-5 * time.Minute), NotAfter: now.AddDate(10, 0, 0),
		IsCA: true, BasicConstraintsValid: true, MaxPathLenZero: true,
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return identity{}, err
	}
	keyPEM, err := encodeKey(key)
	return identity{CA: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})), CAKey: keyPEM}, err
}

func issueCertificate(now time.Time, ca *x509.Certificate, caKey any, names []string) (string, string, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return "", "", err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return "", "", err
	}
	serial.Add(serial, big.NewInt(1))
	template := &x509.Certificate{SerialNumber: serial, Subject: pkix.Name{CommonName: "IBKR Gateway localhost"},
		NotBefore: now.Add(-5 * time.Minute), NotAfter: now.Add(leafLifetime),
		DNSNames: names, IPAddresses: []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")},
		BasicConstraintsValid: true, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, template, ca, &key.PublicKey, caKey)
	if err != nil {
		return "", "", err
	}
	keyPEM, err := encodeKey(key)
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})), keyPEM, err
}

func encodeKey(key *ecdsa.PrivateKey) (string, error) {
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return "", err
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})), nil
}

// A single atomic identity contains both key pairs. A crash cannot publish a
// certificate with the previous key, and concurrent starts share a file lock.
func writeAtomic(path string, data []byte) error {
	f, err := os.CreateTemp(filepath.Dir(path), ".tls-*")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	defer f.Close()
	if err := f.Chmod(0o600); err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
		return err
	}
	if err := f.Sync(); err != nil {
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Rename(f.Name(), path)
}
