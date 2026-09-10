package service

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/nite0x/ibkr-gateway-manager/gateway"
	"github.com/nite0x/ibkr-gateway-manager/internal/appconfig"
)

func TestSharedPublicManagerRequiresCredentials(t *testing.T) {
	base := t.TempDir()
	cfg := testDefaultConfig(base)
	cfg.SharedProxyListenAddr = "0.0.0.0:8089"
	cfg.ProxyTLSTerminated = true
	cfg.PublicURL = "https://manager.example.test"
	cfg.ProxyPublicURLTemplate = "https://{id}.example.test"
	instance := cfg.Gateways["primary"]
	instance.ProxyToken = "instance-secret"
	cfg.Gateways["primary"] = instance
	cfg.Password = ""
	if err := cfg.Validate(base); err == nil || !strings.Contains(err.Error(), "username and password") {
		t.Fatalf("expected shared manager token validation error, got %v", err)
	}
	cfg.Password = "test-password"
	cfg.APIToken = ""
	if err := cfg.Validate(base); err != nil {
		t.Fatal(err)
	}
	handler, err := NewRegistry(filepath.Join(base, "config.json"), cfg, func(c gateway.Config) Gateway { return &fakeGateway{baseURL: c.GatewayURL} })
	if err != nil {
		t.Fatal(err)
	}
	response := httptest.NewRecorder()
	handler.ServeSharedGatewayProxy(response, httptest.NewRequest(http.MethodGet, "https://manager.example.test/management/v1/config", nil))
	if response.Code != http.StatusUnauthorized {
		t.Fatalf("public shared manager without API token accepted by Validate; unauthenticated config GET = %d", response.Code)
	}
}

type mutableTestGateway struct{ fakeGateway }

func (g *mutableTestGateway) Reconfigure(c gateway.Config) error {
	g.baseURL = c.GatewayURL
	return nil
}

func TestConfigSaveFailureRestoresManager(t *testing.T) {
	base := t.TempDir()
	cfg := testDefaultConfig(base)
	manager := &mutableTestGateway{}
	handler, err := NewRegistry(filepath.Join(base, "config.json"), cfg, func(c gateway.Config) Gateway { manager.baseURL = c.GatewayURL; return manager })
	if err != nil {
		t.Fatal(err)
	}
	oldURL := manager.BaseURL()
	updated := handler.currentConfig()
	updated.Gateways = map[string]appconfig.GatewayInstance{}
	instance := handler.currentConfig().Gateways["primary"]
	instance.GatewayPort = 5689
	updated.Gateways["primary"] = instance
	if err := updated.Validate(base); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(handler.configPath, 0700); err != nil {
		t.Fatal(err)
	}
	if err := handler.applyConfig(context.Background(), updated); err == nil {
		t.Fatal("expected save failure")
	}
	if manager.BaseURL() != oldURL {
		t.Fatalf("failed config update changed live manager: before=%s after=%s, published config still=%s", oldURL, manager.BaseURL(), handler.currentConfig().Gateways["primary"].GatewayURL)
	}
}

func TestListenChangeDoesNotDropAuthOnOldListener(t *testing.T) {
	base := t.TempDir()
	cfg := testDefaultConfig(base)
	cfg.ListenAddr = "0.0.0.0:8088"
	cfg.APIToken = "secret"
	handler, err := NewRegistry(filepath.Join(base, "config.json"), cfg, func(c gateway.Config) Gateway { return &fakeGateway{baseURL: c.GatewayURL} })
	if err != nil {
		t.Fatal(err)
	}
	// This listener represents main's server; it retains the same handler/socket after PUT.
	oldServer := httptest.NewServer(handler)
	defer oldServer.Close()
	body, _ := json.Marshal(map[string]any{"gateways": handler.currentConfig().Gateways, "listen_addr": "127.0.0.1:8088", "api_token": ""})
	req, _ := http.NewRequest(http.MethodPut, oldServer.URL+"/management/v1/config", strings.NewReader(string(body)))
	req.Header.Set("Authorization", "Bearer secret")
	resp, err := oldServer.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusBadGateway {
		t.Fatalf("live listener edit was not rejected: %d", resp.StatusCode)
	}
	if handler.currentConfig().APIToken != "secret" || handler.currentConfig().ListenAddr != cfg.ListenAddr {
		t.Fatal("rejected listener edit changed configuration")
	}
	resp, err = oldServer.Client().Get(oldServer.URL + "/management/v1/config")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("old listener remains reachable without credentials after listen_addr changed: status=%d", resp.StatusCode)
	}
}
