package gateway

import (
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"
)

func TestReconfigureCannotOverwriteAnotherManagersIntent(t *testing.T) {
	base := t.TempDir()
	old := Config{GatewayDir: filepath.Join(base, "old"), GatewayPort: 5960}
	destination := Config{GatewayDir: filepath.Join(base, "destination"), GatewayPort: 5961}
	if err := old.NormalizeAndValidate(base); err != nil {
		t.Fatal(err)
	}
	if err := destination.NormalizeAndValidate(base); err != nil {
		t.Fatal(err)
	}
	owner := NewGatewayManager(destination)
	if err := owner.acquireProcessLock(); err != nil {
		t.Fatal(err)
	}
	defer owner.releaseProcessLock()
	if err := owner.setIntent(desiredLoggedOut); err != nil {
		t.Fatal(err)
	}
	g := NewGatewayManager(old)
	if err := g.StopGateway(false); err != nil {
		t.Fatal(err)
	}
	previous := g.Status()
	if err := g.Reconfigure(destination); err == nil || !strings.Contains(err.Error(), "already managing") {
		t.Fatalf("expected destination ownership denial, got %v", err)
	}
	if got := NewGatewayManager(destination).Status().DesiredState; got != desiredLoggedOut {
		t.Fatalf("destination intent overwritten: %s", got)
	}
	if err := g.RestoreConfiguration(old, previous); err != nil {
		t.Fatal(err)
	}
	if g.BaseURL() != old.GatewayURL || g.Status().DesiredState != desiredStopped || g.Status().Running {
		t.Fatalf("failed to restore stopped manager: %+v", g.Status())
	}
}

func TestRestoreConfigurationPreservesIdleIntent(t *testing.T) {
	for _, intent := range []string{desiredConnected, desiredLoggedOut, desiredStopped} {
		t.Run(intent, func(t *testing.T) {
			cfg := Config{GatewayDir: filepath.Join(t.TempDir(), "instance"), GatewayPort: 5962}
			if err := cfg.NormalizeAndValidate(t.TempDir()); err != nil {
				t.Fatal(err)
			}
			g := NewGatewayManager(cfg)
			previous := g.Status()
			previous.DesiredState = intent
			if err := g.RestoreConfiguration(cfg, previous); err != nil {
				t.Fatal(err)
			}
			if g.Status().Running || NewGatewayManager(cfg).Status().DesiredState != intent {
				t.Fatal("restoration started an idle process or lost persisted intent")
			}
		})
	}
}

func TestSessionInvalidationClearsConnectionFlagsAndKeepsJSONContract(t *testing.T) {
	g := NewGatewayManager(Config{GatewayDir: t.TempDir()})
	g.session = SessionSnapshot{Connected: true, Established: true, Competing: true, SessionReady: true}
	g.resetSession()
	if s := g.Status(); s.SessionReady || s.Connected || s.Established || s.Competing {
		t.Fatalf("stale connection flags: %+v", s)
	}
	data, err := json.Marshal(g.Status())
	if err != nil {
		t.Fatal(err)
	}
	var fields map[string]any
	if err := json.Unmarshal(data, &fields); err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"connected", "established", "competing", "session_ready"} {
		if _, exists := fields[key]; !exists {
			t.Fatalf("missing JSON field %s", key)
		}
	}
	if err := g.setIntent("invalid"); err == nil {
		t.Fatal("invalid intent accepted")
	}
}
