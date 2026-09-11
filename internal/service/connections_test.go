package service

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/nite0x/ibkr-gateway-manager/internal/appconfig"
)

func TestConnectionExportRequiresAPITokenAndKeepsStatusRedacted(t *testing.T) {
	s := newTestServer(t, &fakeGateway{}, "manager-key")
	s.config.Gateways = map[string]appconfig.GatewayInstance{
		"alpha":   {ProxyPublicURL: "https://alpha.test", ProxyToken: "alpha-secret", AutoStart: true},
		"stopped": {ProxyPublicURL: "https://stopped.test", ProxyToken: "stopped-secret"},
	}
	cookie := loginCookie(t, s)
	for _, token := range []string{"", "wrong", "alpha-secret", "manager-key"} {
		r := httptest.NewRequest(http.MethodGet, "/management/v1/connections", nil)
		r.AddCookie(cookie)
		if token != "" {
			r.Header.Set("Authorization", "Bearer "+token)
		}
		w := httptest.NewRecorder()
		s.ServeHTTP(w, r)
		if w.Header().Get("Cache-Control") != "no-store" {
			t.Fatal("credential export must not be cached")
		}
		if token != "manager-key" {
			if w.Code != http.StatusUnauthorized || strings.Contains(w.Body.String(), "secret") {
				t.Fatalf("unauthorized export: %d", w.Code)
			}
			continue
		}
		var payload struct {
			Connections []gatewayConnection `json:"connections"`
		}
		if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &payload) != nil {
			t.Fatalf("export: %d", w.Code)
		}
		if len(payload.Connections) != 2 || payload.Connections[0].ProxyToken != "alpha-secret" || payload.Connections[1].ProxyToken != "stopped-secret" {
			t.Fatal("export must include all configured instances and their own tokens")
		}
	}
	for _, path := range []string{"/management/v1/config", "/management/v1/gateways"} {
		w := authCall(s, http.MethodGet, path, "", cookie)
		if w.Code != 200 || strings.Contains(w.Body.String(), "alpha-secret") || strings.Contains(w.Body.String(), "stopped-secret") {
			t.Fatalf("public config/status leaked credentials: %s", path)
		}
	}
}
