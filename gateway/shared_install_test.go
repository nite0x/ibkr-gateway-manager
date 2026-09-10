package gateway

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
)

func sharedTestManager(t *testing.T, dir, id string, port int) *GatewayManager {
	t.Helper()
	cfg := Config{GatewayDir: dir, GatewayConfigFile: "root/conf-" + id + ".yaml", GatewayPort: port}
	if err := cfg.NormalizeAndValidate(t.TempDir()); err != nil {
		t.Fatal(err)
	}
	return NewGatewayManager(cfg)
}

func TestSharedInstallDownloadsOnceAndPreservesConfigs(t *testing.T) {
	t.Setenv("HTTPS_PROXY", "")
	t.Setenv("HTTP_PROXY", "")
	archive := testGatewayArchive(t)
	digest := sha256.Sum256(archive)
	var downloads atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		downloads.Add(1)
		_, _ = w.Write(archive)
	}))
	defer server.Close()
	dir := filepath.Join(t.TempDir(), "shared")
	a := sharedTestManager(t, dir, "alpha", 5682)
	b := sharedTestManager(t, dir, "beta", 5683)
	release := gatewayRelease{Version: "test", URL: server.URL, SHA256: hex.EncodeToString(digest[:]), Size: int64(len(archive))}
	a.release, b.release = release, release
	var wg sync.WaitGroup
	for _, manager := range []*GatewayManager{a, b} {
		wg.Go(func() {
			if err := manager.EnsureInstalled(context.Background()); err != nil {
				t.Error(err)
			}
		})
	}
	wg.Wait()
	if downloads.Load() != 1 {
		t.Fatalf("downloads = %d, want one shared installation", downloads.Load())
	}
	assertConfigs := func() {
		t.Helper()
		for _, manager := range []*GatewayManager{a, b} {
			path := filepath.Join(dir, manager.config.configFile())
			data, err := os.ReadFile(path)
			if err != nil || !strings.Contains(string(data), fmt.Sprintf("listenPort: %d", manager.config.GatewayPort)) {
				t.Fatalf("instance config changed: %s: %s (%v)", path, data, err)
			}
		}
	}
	assertConfigs()
	template, err := os.ReadFile(filepath.Join(dir, "root", "conf.yaml"))
	if err != nil || string(template) != sampleConf {
		t.Fatalf("shared template was modified: %s (%v)", template, err)
	}
	if err := a.installVerifiedRelease(context.Background()); err != nil {
		t.Fatal(err)
	}
	assertConfigs()
	// A config created after the upgrade must survive rollback too.
	c := sharedTestManager(t, dir, "gamma", 5684)
	if err := c.EnsureInstalled(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := a.swapWithRollback(); err != nil {
		t.Fatal(err)
	}
	assertConfigs()
	if !fileExists(filepath.Join(dir, c.config.configFile())) {
		t.Fatal("rollback removed newly created instance config")
	}
}

// A subprocess with the same command/cwd contract as the Java launcher lets
// the lifecycle test exercise real listeners, PID recovery and termination.
func TestGatewayProcessHelper(t *testing.T) {
	if os.Getenv("IBKR_TEST_HELPER") != "1" {
		return
	}
	data, err := os.ReadFile(os.Args[len(os.Args)-1])
	if err != nil {
		t.Fatal(err)
	}
	match := regexp.MustCompile(`listenPort:\s*(\d+)`).FindSubmatch(data)
	if len(match) != 2 {
		t.Fatal("missing listenPort")
	}
	server := &http.Server{Addr: "127.0.0.1:" + string(match[1]), Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"authenticated":false}`))
	})}
	if err := server.ListenAndServe(); err != nil {
		t.Fatal(err)
	}
}

func TestSharedProcessesStartDetachAndStopIndependently(t *testing.T) {
	t.Setenv("IBKR_TEST_HELPER", "1")
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("IBKR_TEST_EXECUTABLE", executable)
	dir := filepath.Join(t.TempDir(), "shared with spaces")
	testGatewayDir(t, dir, "existing")
	script := "#!/bin/sh\nexec \"$IBKR_TEST_EXECUTABLE\" -test.run=^TestGatewayProcessHelper$ -- clientportal.gw \"$1\"\n"
	if err := os.WriteFile(filepath.Join(dir, "bin", "run.sh"), []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	newManager := func(id string) *GatewayManager {
		listener, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		port := listener.Addr().(*net.TCPAddr).Port
		_ = listener.Close()
		manager := sharedTestManager(t, dir, id, port)
		manager.config.GatewayURL = "http://127.0.0.1:" + strconv.Itoa(port)
		t.Cleanup(func() { _ = manager.StopGateway(false) })
		return manager
	}
	a, b := newManager("alpha"), newManager("beta")
	for _, manager := range []*GatewayManager{a, b} {
		if err := manager.StartGateway(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	if err := a.Upgrade(context.Background()); err == nil || !strings.Contains(err.Error(), "stop other instances") {
		t.Fatalf("upgrade should refuse while peer is running: %v", err)
	}
	if !a.isOnline() || !b.isOnline() {
		t.Fatal("rejected upgrade affected running instances")
	}
	if err := a.StopGateway(true); err != nil {
		t.Fatal(err)
	}
	recovered := NewGatewayManager(a.config)
	t.Cleanup(func() { _ = recovered.StopGateway(false) })
	if err := recovered.StartGateway(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := recovered.StopGateway(false); err != nil {
		t.Fatal(err)
	}
	if a.isOnline() || !b.isOnline() {
		t.Fatal("stopping recovered alpha affected beta or failed to stop alpha")
	}
	if !fileExists(processRecordFile(b.config.stateDir())) {
		t.Fatal("stopping alpha removed beta's process record")
	}
}
