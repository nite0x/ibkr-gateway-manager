package gateway

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestBundleVerifiedReleaseAndInstallWithoutNetwork(t *testing.T) {
	t.Setenv("HTTPS_PROXY", "")
	t.Setenv("HTTP_PROXY", "")
	archive := testGatewayArchive(t)
	digest := sha256.Sum256(archive)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write(archive) }))
	defer server.Close()
	release := gatewayRelease{Version: "fixture", URL: server.URL, SHA256: hex.EncodeToString(digest[:]), Size: int64(len(archive))}
	base := t.TempDir()
	bundle := filepath.Join(base, "bundle")
	if err := bundleRelease(context.Background(), bundle, release); err != nil {
		t.Fatal(err)
	}
	manifest, err := readInstallManifest(bundle)
	if err != nil || !manifest.Verified || manifest.ArchiveSHA != release.SHA256 {
		t.Fatalf("unverified bundle: %+v %v", manifest, err)
	}
	conf, err := os.ReadFile(filepath.Join(bundle, "root", "conf.yaml"))
	if err != nil || string(conf) != sampleConf {
		t.Fatal("bundle modified upstream configuration", err)
	}
	if err := bundleRelease(context.Background(), bundle, release); err == nil {
		t.Fatal("overwrote existing bundle")
	}
	server.Close()
	cfg := Config{GatewayDir: filepath.Join(base, "runtime"), GatewayConfigFile: "root/conf-primary.yaml", GatewayStateDir: filepath.Join(base, "state"), BundledGatewayDir: bundle, GatewayPort: 5680}
	if err := cfg.NormalizeAndValidate(base); err != nil {
		t.Fatal(err)
	}
	manager := NewGatewayManager(cfg)
	manager.release.URL = server.URL // Offline: installation must use the bundle.
	if err := manager.EnsureInstalled(context.Background()); err != nil {
		t.Fatal(err)
	}
	for _, relative := range []string{"root/conf.yaml", "root/vertx.jks", "bin/run.sh"} {
		if _, err := os.Stat(filepath.Join(cfg.GatewayDir, relative)); err != nil {
			t.Fatal("incomplete runtime install", err)
		}
	}
	conf, err = os.ReadFile(filepath.Join(bundle, "root", "conf.yaml"))
	if err != nil || string(conf) != sampleConf {
		t.Fatal("runtime modified image template", err)
	}
}

func TestBundleRejectsUnverifiedArchive(t *testing.T) {
	t.Setenv("HTTPS_PROXY", "")
	t.Setenv("HTTP_PROXY", "")
	archive := testGatewayArchive(t)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write(archive) }))
	defer server.Close()
	destination := filepath.Join(t.TempDir(), "bundle")
	err := bundleRelease(context.Background(), destination, gatewayRelease{URL: server.URL, Size: int64(len(archive)), SHA256: strings.Repeat("0", 64)})
	if err == nil {
		t.Fatal("unverified archive accepted")
	}
	if _, err := os.Stat(destination); !os.IsNotExist(err) {
		t.Fatal("failed bundle left a usable destination")
	}
}
