package service

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/nite0x/ibkr-gateway-manager/gateway"
	"github.com/nite0x/ibkr-gateway-manager/internal/appconfig"
)

type transactionGateway struct {
	fakeGateway
	onConfigure  func() error
	onStop       func() error
	restores     int
	restoreError error
}

func (g *transactionGateway) Reconfigure(cfg gateway.Config) error {
	g.baseURL = cfg.GatewayURL
	if g.onConfigure != nil {
		return g.onConfigure()
	}
	return nil
}
func (g *transactionGateway) StartGateway(context.Context) error {
	g.started++
	g.status.Running = true
	return nil
}
func (g *transactionGateway) StopGateway(bool) error {
	g.stopped++
	g.status.Running = false
	if g.onStop != nil {
		return g.onStop()
	}
	return nil
}
func (g *transactionGateway) RestoreConfiguration(cfg gateway.Config, previous gateway.GatewayStatus) error {
	g.restores++
	g.baseURL = cfg.GatewayURL
	g.status = previous
	return g.restoreError
}

func transactionTestServer(t *testing.T, ids ...string) (*Server, map[string]*transactionGateway) {
	t.Helper()
	base := t.TempDir()
	cfg := appconfig.Config{Username: "admin", Password: "test-password", SessionTTLMinutes: 30, ListenAddr: "127.0.0.1:8088", PublicURL: "http://127.0.0.1:8088", Gateways: map[string]appconfig.GatewayInstance{}}
	for i, id := range ids {
		cfg.Gateways[id] = appconfig.GatewayInstance{Config: gateway.Config{GatewayDir: filepath.Join(base, id), GatewayPort: 5800 + i}}
	}
	managers := map[string]*transactionGateway{}
	s, err := NewRegistry(filepath.Join(base, "config.json"), cfg, func(c gateway.Config) Gateway {
		g := &transactionGateway{fakeGateway: fakeGateway{baseURL: c.GatewayURL}}
		g.status.DesiredState = "connected"
		managers[filepath.Base(c.GatewayDir)] = g
		return g
	})
	if err != nil {
		t.Fatal(err)
	}
	return s, managers
}

func TestConfigCommitFailureCompensatesAllProcessChanges(t *testing.T) {
	s, managers := transactionTestServer(t, "alpha", "gamma")
	managers["alpha"].status.Running = true
	managers["gamma"].status.Running = true
	managers["gamma"].status.DesiredState = "logged_out"
	old := s.currentConfig()
	updated := old.Clone()
	a := updated.Gateways["alpha"]
	a.GatewayPort = 5810
	a.GatewayURL = ""
	updated.Gateways["alpha"] = a
	updated.Gateways["beta"] = appconfig.GatewayInstance{AutoStart: true, Config: gateway.Config{GatewayDir: filepath.Join(filepath.Dir(s.configPath), "beta"), GatewayPort: 5811, GatewayLifecycle: gateway.LifecyclePersistent}}
	delete(updated.Gateways, "gamma")
	if err := updated.Validate(filepath.Dir(s.configPath)); err != nil {
		t.Fatal(err)
	}
	// A filesystem change after staging forces the final rename to fail.
	managers["gamma"].onStop = func() error { return os.Mkdir(s.configPath, 0700) }
	err := s.applyConfig(context.Background(), updated)
	if err == nil || !strings.Contains(err.Error(), "save config") {
		t.Fatalf("expected commit failure, got %v", err)
	}
	if !reflect.DeepEqual(old, s.currentConfig()) {
		t.Fatal("failed commit published new config")
	}
	if managers["alpha"].BaseURL() != old.Gateways["alpha"].GatewayURL || !managers["alpha"].status.Running {
		t.Fatal("modified manager was not restored")
	}
	if !managers["gamma"].status.Running || managers["gamma"].status.DesiredState != "logged_out" {
		t.Fatal("removed manager lost its previous intent")
	}
	if managers["beta"].started != 1 || managers["beta"].stopped != 1 || managers["beta"].status.Running {
		t.Fatal("unpublished persistent manager was not stopped")
	}
	if _, exists := s.gateway("beta"); exists {
		t.Fatal("unpublished manager leaked into registry")
	}
	files, _ := filepath.Glob(filepath.Join(filepath.Dir(s.configPath), ".config-*.json"))
	if len(files) != 0 {
		t.Fatalf("staged files leaked: %v", files)
	}
}

func TestConfigMutationFailureRestoresFailingAndEarlierManagers(t *testing.T) {
	s, managers := transactionTestServer(t, "alpha", "beta")
	old := s.currentConfig()
	updated := old.Clone()
	for id, c := range updated.Gateways {
		c.GatewayProxyHost = "https://example.test"
		updated.Gateways[id] = c
	}
	managers["beta"].onConfigure = func() error { return errors.New("start failed after mutation") }
	managers["alpha"].restoreError = errors.New("old process could not restart")
	err := s.applyConfig(context.Background(), updated)
	if err == nil || !strings.Contains(err.Error(), "start failed after mutation") || !strings.Contains(err.Error(), "old process could not restart") {
		t.Fatalf("lost operation or compensation error: %v", err)
	}
	if managers["alpha"].restores != 1 || managers["beta"].restores != 1 {
		t.Fatal("not all attempted changes were compensated")
	}
	if !reflect.DeepEqual(old, s.currentConfig()) {
		t.Fatal("failed mutation published configuration")
	}
}

func TestListenerPreparationFailureHasNoProcessSideEffects(t *testing.T) {
	s, managers := transactionTestServer(t, "alpha")
	if err := s.StartProxyListeners(); err != nil {
		t.Fatal(err)
	}
	defer s.ShutdownProxyListeners(context.Background())
	occupied, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer occupied.Close()
	updated := s.currentConfig()
	a := updated.Gateways["alpha"]
	a.ProxyListenAddr = occupied.Addr().String()
	a.ProxyPublicURL = "http://" + a.ProxyListenAddr
	a.AutoStart = true
	updated.Gateways["alpha"] = a
	if err := updated.Validate(filepath.Dir(s.configPath)); err != nil {
		t.Fatal(err)
	}
	if err := s.applyConfig(context.Background(), updated); err == nil {
		t.Fatal("expected listener bind error")
	}
	if managers["alpha"].started != 0 || managers["alpha"].stopped != 0 || managers["alpha"].restores != 0 {
		t.Fatal("listener preparation mutated a process")
	}
}

func TestConfigSnapshotsAreIndependentAndRotationRevokesOnlyAffectedSessions(t *testing.T) {
	s, _ := transactionTestServer(t, "alpha", "beta")
	old := s.currentConfig()
	delete(old.Gateways, "alpha")
	if _, exists := s.currentConfig().Gateways["alpha"]; !exists {
		t.Fatal("snapshot shares the live map")
	}
	for _, id := range []string{"alpha", "beta"} {
		s.sessions[id] = browserSession{GatewayID: id, Expires: time.Now().Add(time.Hour)}
		s.tickets[id] = loginTicket{GatewayID: id, Expires: time.Now().Add(time.Hour)}
	}
	updated := s.currentConfig()
	a := updated.Gateways["alpha"]
	a.ProxyToken = "new-secret"
	updated.Gateways["alpha"] = a
	if err := s.applyConfig(context.Background(), updated); err != nil {
		t.Fatal(err)
	}
	if len(s.sessions) != 1 || len(s.tickets) != 1 || s.sessions["beta"].GatewayID != "beta" {
		t.Fatal("rotation did not revoke only alpha")
	}
	delete(updated.Gateways, "beta")
	if err := s.applyConfig(context.Background(), updated); err != nil {
		t.Fatal(err)
	}
	if len(s.sessions) != 0 || len(s.tickets) != 0 {
		t.Fatal("removed gateway retained browser credentials")
	}
}

func TestEmbeddedManagerAssets(t *testing.T) {
	s := newTestServer(t, &fakeGateway{}, "")
	for path, contentType := range map[string]string{"/manager/": "text/html", "/manager/manager.js": "text/javascript", "/manager/manager.css": "text/css"} {
		for _, method := range []string{http.MethodGet, http.MethodHead} {
			w := httptest.NewRecorder()
			s.ServeHTTP(w, httptest.NewRequest(method, path, nil))
			if w.Code != http.StatusOK || !strings.HasPrefix(w.Header().Get("Content-Type"), contentType) {
				t.Fatalf("%s %s = %d", method, path, w.Code)
			}
			if method == http.MethodGet && w.Body.Len() == 0 {
				t.Fatal("empty embedded asset")
			}
			if method == http.MethodHead && w.Body.Len() != 0 {
				t.Fatal("HEAD returned a body")
			}
			if strings.Contains(w.Header().Get("Content-Security-Policy"), "unsafe-inline") {
				t.Fatal("inline scripts remain allowed")
			}
		}
	}
}
