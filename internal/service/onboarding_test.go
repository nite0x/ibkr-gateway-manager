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

func TestEmptyDeploymentCreateAndRemoveLastInstance(t *testing.T) {
	base := t.TempDir()
	cfg := appconfig.Default(base)
	cfg.Username, cfg.Password, cfg.APIToken = "admin", "test-password", "manager-secret"
	cfg.SharedProxyListenAddr = freeTCPAddress(t)
	cfg.ProxyTLSTerminated = true
	cfg.PublicURL = "https://manager.example.test"
	cfg.ProxyPublicURLTemplate = "https://{id}.example.test"
	created := 0
	manager := &fakeGateway{}
	handler, err := NewRegistry(filepath.Join(base, "config.json"), cfg, func(c gateway.Config) Gateway {
		created++
		manager.baseURL = c.GatewayURL
		return manager
	})
	if err != nil {
		t.Fatal(err)
	}
	defer handler.ShutdownProxyListeners(context.Background())
	if created != 0 {
		t.Fatal("empty startup created a Gateway manager")
	}
	put := func(body, token string, want int) {
		t.Helper()
		req := httptest.NewRequest(http.MethodPut, "/management/v1/config", strings.NewReader(body))
		if token != "" {
			req.Header.Set("Authorization", "Bearer "+token)
		}
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, req)
		if response.Code != want {
			t.Fatalf("PUT returned %d, want %d: %s", response.Code, want, response.Body.String())
		}
	}
	body := `{"gateways":{"primary":{"use_global_defaults":true,"gateway_port":5680,"auto_start":false}}}`
	put(body, "", http.StatusUnauthorized)
	if created != 0 {
		t.Fatal("unauthenticated request created a Gateway")
	}
	put(body, "manager-secret", http.StatusOK)
	first := handler.currentConfig().Gateways["primary"]
	if len(first.ProxyToken) != 64 || first.ProxyToken == cfg.APIToken {
		t.Fatal("instance token was not generated independently")
	}
	if created != 1 || manager.started != 0 {
		t.Fatal("manual-start creation started Java")
	}
	loaded, err := appconfig.LoadOrCreate(handler.configPath)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.Gateways["primary"].ProxyToken != first.ProxyToken {
		t.Fatal("token did not persist")
	}
	put(body, "manager-secret", http.StatusOK)
	if handler.currentConfig().Gateways["primary"].ProxyToken != first.ProxyToken {
		t.Fatal("blank token edit rotated existing token")
	}
	for _, bad := range []string{`{}`, `{"gateways":null}`} {
		put(bad, "manager-secret", http.StatusBadRequest)
		if len(handler.currentConfig().Gateways) != 1 {
			t.Fatal("missing/null gateways removed an instance")
		}
	}
	request := httptest.NewRequest(http.MethodGet, "/management/v1/config", nil)
	request.Header.Set("Authorization", "Bearer manager-secret")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if strings.Contains(response.Body.String(), first.ProxyToken) {
		t.Fatal("GET config exposed instance token")
	}
	// Deleting an instance removes its configuration and process, not its files.
	if err := os.MkdirAll(first.GatewayStateDir, 0700); err != nil {
		t.Fatal(err)
	}
	marker := filepath.Join(first.GatewayStateDir, "keep-data")
	if err := os.WriteFile(marker, []byte("existing data"), 0600); err != nil {
		t.Fatal(err)
	}
	put(`{"gateways":{}}`, "manager-secret", http.StatusOK)
	if manager.stopped != 1 || len(handler.currentConfig().Gateways) != 0 {
		t.Fatal("last instance was not removed")
	}
	if _, err := os.Stat(marker); err != nil {
		t.Fatal("instance removal deleted data", err)
	}
	loaded, err = appconfig.LoadOrCreate(handler.configPath)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.Gateways == nil || len(loaded.Gateways) != 0 {
		t.Fatal("reload restored default instance")
	}
	reloaded, err := NewRegistry(handler.configPath, loaded, func(c gateway.Config) Gateway { t.Fatal("restart recreated an instance"); return nil })
	if err != nil {
		t.Fatal(err)
	}
	request = httptest.NewRequest(http.MethodGet, "/management/v1/gateways", nil)
	request.Header.Set("Authorization", "Bearer manager-secret")
	response = httptest.NewRecorder()
	reloaded.ServeHTTP(response, request)
	var result struct {
		Gateways []json.RawMessage `json:"gateways"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	if response.Code != 200 || result.Gateways == nil || len(result.Gateways) != 0 {
		t.Fatalf("empty list: %s", response.Body.String())
	}
}
