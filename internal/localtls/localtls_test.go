package localtls

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"sync"
	"testing"
	"time"
)

func TestIdentityPersistsAndRenewsWithoutChangingTrust(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "tls")
	m, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	first := m.certificate
	status, caPEM, err := Inspect(dir)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(caPEM, []byte("PRIVATE")) {
		t.Fatal("export contains a private key")
	}
	roots := x509.NewCertPool()
	roots.AppendCertsFromPEM(caPEM)
	for _, host := range []string{"localhost", "manager.localhost", "primary.localhost", "paper.localhost", "127.0.0.1", "::1"} {
		if _, err := first.Leaf.Verify(x509.VerifyOptions{Roots: roots, DNSName: host}); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := m.GetCertificate(&tls.ClientHelloInfo{ServerName: "example.com"}); err == nil {
		t.Fatal("served non-local name")
	}
	for _, name := range []string{stateName, "ca.crt"} {
		info, err := os.Stat(filepath.Join(dir, name))
		if err != nil || info.Mode().Perm() != 0o600 {
			t.Fatalf("permissions for %s: %v %v", name, info, err)
		}
	}
	info, _ := os.Stat(dir)
	if info.Mode().Perm() != 0o700 {
		t.Fatal("directory is not private")
	}
	second, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(first.Certificate[0], second.certificate.Certificate[0]) {
		t.Fatal("restart replaced certificate")
	}
	future := first.Leaf.NotAfter.Add(-renewBefore + time.Hour)
	second.now = func() time.Time { return future }
	renewed, err := second.GetCertificate(&tls.ClientHelloInfo{ServerName: "new-instance.localhost"})
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(first.Certificate[0], renewed.Certificate[0]) {
		t.Fatal("certificate was not renewed")
	}
	if _, err := renewed.Leaf.Verify(x509.VerifyOptions{Roots: roots, CurrentTime: future, DNSName: "new-instance.localhost"}); err != nil {
		t.Fatal(err)
	}
	after, nextCA, _ := Inspect(dir)
	if status.CAFingerprint != after.CAFingerprint || !bytes.Equal(caPEM, nextCA) {
		t.Fatal("renewal changed CA")
	}
	third := &Manager{dir: dir, now: func() time.Time { return future }}
	if err := third.refresh(); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(renewed.Certificate[0], third.certificate.Certificate[0]) {
		t.Fatal("renewed certificate was not persisted")
	}
}

func TestConcurrentFirstStartSharesOneCA(t *testing.T) {
	dir := t.TempDir()
	var wg sync.WaitGroup
	results := make(chan string, 8)
	for i := 0; i < 8; i++ {
		wg.Go(func() {
			m, err := Open(dir)
			if err != nil {
				t.Error(err)
				return
			}
			results <- string(m.ca.Raw)
		})
	}
	wg.Wait()
	close(results)
	var first string
	for ca := range results {
		if first == "" {
			first = ca
		}
		if ca != first {
			t.Fatal("concurrent starts generated different roots")
		}
	}
}

func TestDamagedIdentityDoesNotRotateCA(t *testing.T) {
	for _, damaged := range []string{"broken", "{}", "missing"} {
		t.Run(damaged, func(t *testing.T) {
			dir := t.TempDir()
			if _, err := Open(dir); err != nil {
				t.Fatal(err)
			}
			ca, _ := os.ReadFile(filepath.Join(dir, "ca.crt"))
			if damaged == "missing" {
				_ = os.Remove(filepath.Join(dir, stateName))
			} else {
				_ = os.WriteFile(filepath.Join(dir, stateName), []byte(damaged), 0o600)
			}
			if _, err := Open(dir); err == nil {
				t.Fatal("damaged identity was accepted")
			}
			after, _ := os.ReadFile(filepath.Join(dir, "ca.crt"))
			if !bytes.Equal(ca, after) {
				t.Fatal("CA replaced on error")
			}
		})
	}
}

func TestExpiredLeafRenewsAndExpiredCARemainsUnchanged(t *testing.T) {
	dir := t.TempDir()
	m, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	now := m.certificate.Leaf.NotAfter.Add(time.Hour)
	m.now = func() time.Time { return now }
	if _, err := m.GetCertificate(nil); err != nil {
		t.Fatal(err)
	}
	before, _ := os.ReadFile(filepath.Join(dir, stateName))
	now = m.ca.NotAfter.Add(time.Hour)
	if _, err := m.GetCertificate(nil); err == nil {
		t.Fatal("expired CA accepted")
	}
	after, _ := os.ReadFile(filepath.Join(dir, stateName))
	if !bytes.Equal(before, after) {
		t.Fatal("expired CA automatically replaced")
	}
}

func TestMismatchedPrivateKeyRejected(t *testing.T) {
	dir := t.TempDir()
	if _, err := Open(dir); err != nil {
		t.Fatal(err)
	}
	state, _ := readIdentity(dir)
	other, _ := newIdentity(time.Now())
	state.CAKey = other.CAKey
	data, _ := json.Marshal(state)
	_ = os.WriteFile(filepath.Join(dir, stateName), data, 0o600)
	if _, err := Open(dir); err == nil {
		t.Fatal("mismatched CA key accepted")
	}
}

func TestCoversHost(t *testing.T) {
	for _, host := range []string{"evil.localhost.com", "a.b.localhost", "bad_name.localhost", "-bad.localhost", "example.com", "localhost.", "127.0.0.2"} {
		if CoversHost(host) {
			t.Fatalf("accepted %q", host)
		}
	}
}

func TestExplicitInstanceNamesUpdateWithoutChangingCA(t *testing.T) {
	dir := t.TempDir()
	m, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	before := string(m.ca.Raw)
	if err := m.EnsureHosts([]string{"paper.localhost", "second.localhost"}); err != nil {
		t.Fatal(err)
	}
	if string(m.ca.Raw) != before {
		t.Fatal("adding a name rotated the CA")
	}
	for _, host := range []string{"manager.localhost", "primary.localhost", "paper.localhost", "second.localhost"} {
		if !slices.Contains(m.certificate.Leaf.DNSNames, host) {
			t.Fatalf("missing explicit SAN: %s", host)
		}
	}
	next, err := Open(dir, "third.localhost")
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(next.certificate.Leaf.DNSNames, "paper.localhost") || !slices.Contains(next.certificate.Leaf.DNSNames, "third.localhost") {
		t.Fatal("SANs were lost on restart")
	}
}
