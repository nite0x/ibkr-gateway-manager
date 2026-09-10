package gateway

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

func testGatewayArchive(t *testing.T) []byte {
	t.Helper()
	var buffer bytes.Buffer
	writer := zip.NewWriter(&buffer)
	files := []struct {
		name string
		body string
		mode os.FileMode
	}{
		{name: "root/conf.yaml", body: sampleConf, mode: 0o600},
		{name: "root/vertx.jks", body: "certificate", mode: 0o600},
		{name: "bin/run.sh", body: "#!/bin/sh\n", mode: 0o755},
	}
	for _, file := range files {
		header := &zip.FileHeader{Name: file.name, Method: zip.Deflate}
		header.SetMode(file.mode)
		entry, err := writer.CreateHeader(header)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := io.WriteString(entry, file.body); err != nil {
			t.Fatal(err)
		}
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	return buffer.Bytes()
}

func TestRequestedLocalVersionDoesNotFallBackToDownload(t *testing.T) {
	requests := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		http.Error(w, "unexpected release download", http.StatusInternalServerError)
	}))
	defer server.Close()
	base := t.TempDir()
	cfg := Config{GatewayDir: filepath.Join(base, "independent"), BundledGatewayDir: filepath.Join(base, "missing-version")}
	if err := cfg.NormalizeAndValidate(base); err != nil {
		t.Fatal(err)
	}
	manager := NewGatewayManager(cfg)
	manager.release.URL = server.URL
	err := manager.EnsureInstalled(context.Background())
	if err == nil || !strings.Contains(err.Error(), "bundled_gateway_dir") {
		t.Fatalf("expected invalid local version error, got %v", err)
	}
	if requests != 0 || gatewayInstalled(cfg.GatewayDir) {
		t.Fatal("invalid requested version must not download or install another release")
	}
}

func testGatewayDir(t *testing.T, dir, version string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Join(dir, "root"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(dir, "bin"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "root", "conf.yaml"), []byte(sampleConf), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "bin", "run.sh"), []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := writeInstallManifest(dir, gatewayInstallManifest{Version: version, InstalledAt: "2026-01-01T00:00:00Z"}); err != nil {
		t.Fatal(err)
	}
}

func TestVerifiedReleaseInstallsAtomicallyAndCanRollback(t *testing.T) {
	t.Setenv("HTTPS_PROXY", "")
	t.Setenv("HTTP_PROXY", "")
	archive := testGatewayArchive(t)
	digest := sha256.Sum256(archive)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Length", strconv.Itoa(len(archive)))
		_, _ = w.Write(archive)
	}))
	defer server.Close()

	live := filepath.Join(t.TempDir(), "ibkr-gateway")
	testGatewayDir(t, live, "old-version")
	manager := NewGatewayManager(Config{
		GatewayDir:       live,
		GatewayPort:      5680,
		GatewayProxyHost: "https://api.ibkr.com",
		GatewayAllowIPs:  []string{"127.0.0.1"},
	})
	manager.release = gatewayRelease{
		Version: "test-version",
		URL:     server.URL,
		SHA256:  hex.EncodeToString(digest[:]),
		Size:    int64(len(archive)),
	}

	if err := manager.installVerifiedRelease(context.Background()); err != nil {
		t.Fatal(err)
	}
	manifest, err := readInstallManifest(live)
	if err != nil {
		t.Fatal(err)
	}
	if manifest.Version != "test-version" || !manifest.Verified {
		t.Fatalf("unexpected active manifest: %+v", manifest)
	}
	conf, err := os.ReadFile(filepath.Join(live, "root", "conf.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(conf), "listenPort: 5680") {
		t.Fatalf("staged config was not patched: %s", conf)
	}
	if !gatewayInstalled(rollbackGatewayDir(live)) {
		t.Fatal("expected previous installation to be retained")
	}

	if err := manager.swapWithRollback(); err != nil {
		t.Fatal(err)
	}
	manifest, err = readInstallManifest(live)
	if err != nil {
		t.Fatal(err)
	}
	if manifest.Version != "old-version" {
		t.Fatalf("expected old version after rollback, got %q", manifest.Version)
	}
}

func TestVerifiedReleaseRejectsWrongDigestWithoutReplacingLive(t *testing.T) {
	t.Setenv("HTTPS_PROXY", "")
	t.Setenv("HTTP_PROXY", "")
	archive := testGatewayArchive(t)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(archive)
	}))
	defer server.Close()

	live := filepath.Join(t.TempDir(), "ibkr-gateway")
	testGatewayDir(t, live, "safe-version")
	manager := NewGatewayManager(Config{GatewayDir: live})
	manager.release = gatewayRelease{
		Version: "tampered",
		URL:     server.URL,
		SHA256:  strings.Repeat("0", 64),
		Size:    int64(len(archive)),
	}

	err := manager.installVerifiedRelease(context.Background())
	if err == nil || !strings.Contains(err.Error(), "SHA-256 mismatch") {
		t.Fatalf("expected digest mismatch, got %v", err)
	}
	manifest, readErr := readInstallManifest(live)
	if readErr != nil {
		t.Fatal(readErr)
	}
	if manifest.Version != "safe-version" {
		t.Fatalf("live installation was replaced after failed verification: %+v", manifest)
	}
}

func TestAuditSanitizesSecrets(t *testing.T) {
	got := sanitizeAuditValue("authorization=Bearer secret token=abc password:plain cookie=session; proxy=https://user:pass@example.com")
	for _, secret := range []string{"Bearer", "secret", "abc", "plain", "session", "user:pass"} {
		if strings.Contains(got, secret) {
			t.Fatalf("secret %q was not redacted from %q", secret, got)
		}
	}
}

func TestGatewayManagerLockIsExclusive(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "ibkr-gateway")
	first := NewGatewayManager(Config{GatewayDir: dir})
	second := NewGatewayManager(Config{GatewayDir: dir})
	if err := first.acquireProcessLock(); err != nil {
		t.Fatal(err)
	}
	defer first.releaseProcessLock()
	if err := second.acquireProcessLock(); err == nil {
		t.Fatal("expected a second gateway manager to be rejected")
	}
	first.releaseProcessLock()
	if err := second.acquireProcessLock(); err != nil {
		t.Fatalf("expected lock to be reusable: %v", err)
	}
	second.releaseProcessLock()
}

func TestGatewayManagerLocksAreIndependentAcrossDirectories(t *testing.T) {
	baseDir := t.TempDir()
	first := NewGatewayManager(Config{GatewayDir: filepath.Join(baseDir, "first")})
	second := NewGatewayManager(Config{GatewayDir: filepath.Join(baseDir, "second")})
	if err := first.acquireProcessLock(); err != nil {
		t.Fatal(err)
	}
	defer first.releaseProcessLock()
	if err := second.acquireProcessLock(); err != nil {
		t.Fatalf("second independent manager was blocked: %v", err)
	}
	second.releaseProcessLock()
}
