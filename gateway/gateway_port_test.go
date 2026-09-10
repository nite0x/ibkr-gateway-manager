package gateway

import (
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const sampleConf = `    ip2loc: "US"
    proxyRemoteSsl: true
    proxyRemoteHost: "https://api.ibkr.com"
    listenPort: 5001
    listenSsl: true
    ips:
      allow:
        - 192.*
        - 127.0.0.1
      deny:
        - 212.90.324.10
`

func writeConf(t *testing.T, content string) string {
	t.Helper()
	dir := t.TempDir()
	conf := filepath.Join(dir, "conf.yaml")
	if err := os.WriteFile(conf, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	return conf
}

// --- patchListenPort (legacy) ---

func TestPatchListenPortIndented(t *testing.T) {
	conf := writeConf(t, "    ip2loc: \"US\"\n    listenPort: 5001\n    listenSsl: true\n")
	if err := patchListenPort(conf, 5680); err != nil {
		t.Fatal(err)
	}
	data, _ := os.ReadFile(conf)
	want := "    listenPort: 5680"
	if string(data) != "    ip2loc: \"US\"\n"+want+"\n    listenSsl: true\n" {
		t.Fatalf("unexpected conf:\n%s", data)
	}
}

// --- patchGatewayConf ---

func TestPatchGatewayConf_Port(t *testing.T) {
	conf := writeConf(t, sampleConf)
	cfg := Config{
		GatewayPort:      5680,
		GatewayProxyHost: "https://api.ibkr.com",
		GatewayAllowIPs:  []string{"127.0.0.1"},
	}
	if err := patchGatewayConf(conf, cfg); err != nil {
		t.Fatal(err)
	}
	data, _ := os.ReadFile(conf)
	if !strings.Contains(string(data), "listenPort: 5680") {
		t.Fatalf("listenPort not updated:\n%s", data)
	}
}

func TestPatchGatewayConf_ProxyHost(t *testing.T) {
	conf := writeConf(t, sampleConf)
	cfg := Config{
		GatewayPort:      5001,
		GatewayProxyHost: "https://paper-api.ibkr.com",
		GatewayAllowIPs:  []string{"127.0.0.1"},
	}
	if err := patchGatewayConf(conf, cfg); err != nil {
		t.Fatal(err)
	}
	data, _ := os.ReadFile(conf)
	if !strings.Contains(string(data), "paper-api.ibkr.com") {
		t.Fatalf("proxyRemoteHost not updated:\n%s", data)
	}
}

func TestPatchGatewayConf_AllowIPs(t *testing.T) {
	conf := writeConf(t, sampleConf)
	cfg := Config{
		GatewayPort:      5001,
		GatewayProxyHost: "https://api.ibkr.com",
		GatewayAllowIPs:  []string{"127.0.0.1", "10.0.0.1"},
	}
	if err := patchGatewayConf(conf, cfg); err != nil {
		t.Fatal(err)
	}
	data, _ := os.ReadFile(conf)
	s := string(data)
	if !strings.Contains(s, "- 127.0.0.1") || !strings.Contains(s, "- 10.0.0.1") {
		t.Fatalf("allow IPs not updated:\n%s", s)
	}
	// Old entry should be gone.
	if strings.Contains(s, "- 192.*") {
		t.Fatalf("old IP still present:\n%s", s)
	}
}

func TestPatchGatewayConf_DenyUnchanged(t *testing.T) {
	conf := writeConf(t, sampleConf)
	cfg := Config{
		GatewayPort:      5001,
		GatewayProxyHost: "https://api.ibkr.com",
		GatewayAllowIPs:  []string{"127.0.0.1"},
	}
	if err := patchGatewayConf(conf, cfg); err != nil {
		t.Fatal(err)
	}
	data, _ := os.ReadFile(conf)
	// deny block must be untouched.
	if !strings.Contains(string(data), "- 212.90.324.10") {
		t.Fatalf("deny block was modified:\n%s", data)
	}
}

func TestTickleSendsEmptyJSONObject(t *testing.T) {
	var body string
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/api/tickle" {
			http.NotFound(w, r)
			return
		}
		data, err := io.ReadAll(r.Body)
		if err != nil {
			t.Fatal(err)
		}
		body = string(data)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"authenticated":true}`))
	}))
	defer server.Close()

	manager := NewGatewayManager(Config{GatewayURL: server.URL})
	manager.tickle()
	if body != "{}" {
		t.Fatalf("expected tickle body {}, got %q", body)
	}
}

func TestGatewayShutdownLifecycle(t *testing.T) {
	persistent := NewGatewayManager(Config{
		GatewayDir:       t.TempDir(),
		GatewayLifecycle: LifecyclePersistent,
	})
	if err := persistent.Shutdown(); err != nil {
		t.Fatal(err)
	}
	if got := persistent.Status().State; got != gatewayStateDetached {
		t.Fatalf("persistent shutdown state: got %q", got)
	}

	managed := NewGatewayManager(Config{
		GatewayDir:       t.TempDir(),
		GatewayLifecycle: LifecycleManaged,
	})
	if err := managed.Shutdown(); err != nil {
		t.Fatal(err)
	}
	if got := managed.Status().State; got != gatewayStateStopped {
		t.Fatalf("managed shutdown state: got %q", got)
	}
}

func TestGatewayProcessRecordRoundTrip(t *testing.T) {
	dir := t.TempDir()
	manager := NewGatewayManager(Config{GatewayDir: dir, GatewayPort: 5680})
	record := gatewayProcessRecord{
		Version: 1, PID: os.Getpid(), WrapperPID: 42,
		StartedAt: "test-start", GatewayDir: dir, GatewayPort: 5680,
	}
	if err := manager.writeProcessRecord(record); err != nil {
		t.Fatal(err)
	}
	got, err := readProcessRecord(processRecordFile(dir))
	if err != nil {
		t.Fatal(err)
	}
	if got != record {
		t.Fatalf("got %#v, want %#v", got, record)
	}
	pid, err := readPIDFile(pidFile(dir))
	if err != nil || pid != os.Getpid() {
		t.Fatalf("pid file: pid=%d err=%v", pid, err)
	}
}

func TestSecureRuntimePermissionsAndLogRetention(t *testing.T) {
	gatewayDir := t.TempDir()
	for _, dir := range []string{"root", "logs", ".vertx/cache"} {
		if err := os.MkdirAll(filepath.Join(gatewayDir, dir), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	for _, file := range []string{"root/conf.yaml", "root/vertx.jks", "gateway.pid", ".vertx/cache/vertx.jks"} {
		if err := os.WriteFile(filepath.Join(gatewayDir, file), []byte("test"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	oldLog := filepath.Join(gatewayDir, "logs", "gw.old.log")
	newLog := filepath.Join(gatewayDir, "logs", "gw.current.log")
	for _, file := range []string{oldLog, newLog} {
		if err := os.WriteFile(file, []byte("sensitive"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	oldTime := time.Now().Add(-gatewayLogRetention - time.Hour)
	if err := os.Chtimes(oldLog, oldTime, oldTime); err != nil {
		t.Fatal(err)
	}

	manager := NewGatewayManager(Config{GatewayDir: gatewayDir})
	if err := manager.secureRuntimePermissions(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(oldLog); !os.IsNotExist(err) {
		t.Fatalf("expected expired log to be removed, got %v", err)
	}
	for _, path := range []string{gatewayDir, filepath.Join(gatewayDir, "logs"), filepath.Join(gatewayDir, ".vertx")} {
		info, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		if got := info.Mode().Perm(); got != 0o700 {
			t.Fatalf("expected %s mode 0700, got %o", path, got)
		}
	}
	for _, path := range []string{filepath.Join(gatewayDir, "root", "conf.yaml"), newLog, filepath.Join(gatewayDir, ".vertx/cache/vertx.jks")} {
		info, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		if got := info.Mode().Perm(); got != 0o600 {
			t.Fatalf("expected %s mode 0600, got %o", path, got)
		}
	}
}
