package gateway

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

func newRunningOwnershipTestManager(t *testing.T) *GatewayManager {
	t.Helper()
	t.Setenv("IBKR_TEST_HELPER", "1")
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("IBKR_TEST_EXECUTABLE", exe)
	dir := filepath.Join(t.TempDir(), "gateway")
	testGatewayDir(t, dir, "test")
	script := "#!/bin/sh\nexec \"$IBKR_TEST_EXECUTABLE\" -test.run=^TestGatewayProcessHelper$ -- clientportal.gw \"$1\"\n"
	if err := os.WriteFile(filepath.Join(dir, "bin/run.sh"), []byte(script), 0700); err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := listener.Addr().(*net.TCPAddr).Port
	listener.Close()
	cfg := Config{GatewayDir: dir, GatewayPort: port, GatewayURL: "http://127.0.0.1:" + strconv.Itoa(port)}
	if err := cfg.NormalizeAndValidate(t.TempDir()); err != nil {
		t.Fatal(err)
	}
	owner := NewGatewayManager(cfg)
	if err := owner.StartGateway(context.Background()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = owner.StopGateway(false) })
	return owner
}

func TestLifecycleCannotKillAnotherManagerProcess(t *testing.T) {
	owner := newRunningOwnershipTestManager(t)
	contender := NewGatewayManager(owner.config)
	for name, operation := range map[string]func() error{"reconnect": contender.Reconnect, "shutdown": contender.Shutdown, "stop": func() error { return contender.StopGateway(false) }} {
		t.Run(name, func(t *testing.T) {
			err := operation()
			if err == nil || !strings.Contains(err.Error(), "already managing") {
				t.Fatalf("expected ownership denial, got %v", err)
			}
			if !owner.isOnline() {
				t.Fatal("operation killed another manager's process")
			}
		})
	}
}

func TestRestoreConfigurationRestartsPreviouslyRunningLoggedOutProcess(t *testing.T) {
	owner := newRunningOwnershipTestManager(t)
	// The helper's logout response is intentionally unconfirmed; intent still persists.
	_ = owner.Logout(context.Background())
	previous := owner.Status()
	original := owner.config
	if !previous.Running || previous.DesiredState != desiredLoggedOut {
		t.Fatalf("invalid test setup: %+v", previous)
	}
	changed := original
	changed.GatewayDir = filepath.Join(t.TempDir(), "different")
	changed.GatewayStateDir = changed.GatewayDir
	if err := owner.Reconfigure(changed); err != nil {
		t.Fatal(err)
	}
	if owner.isOnline() {
		t.Fatal("logged-out reconfiguration should leave the old process stopped")
	}
	if err := owner.RestoreConfiguration(original, previous); err != nil {
		t.Fatal(err)
	}
	if !owner.isOnline() || owner.Status().DesiredState != desiredLoggedOut || owner.Status().SessionReady {
		t.Fatalf("wrong restored state: %+v", owner.Status())
	}
}
