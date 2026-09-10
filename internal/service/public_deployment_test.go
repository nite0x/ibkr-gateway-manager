package service

import (
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/nite0x/ibkr-gateway-manager/gateway"
	"github.com/nite0x/ibkr-gateway-manager/internal/appconfig"
)

func TestFourSettingDeploymentLoginAndGatewayRouting(t *testing.T) {
	_, port, err := net.SplitHostPort(freeTCPAddress(t))
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("IBKR_GATEWAY_MANAGER_USERNAME", "admin")
	t.Setenv("IBKR_GATEWAY_MANAGER_PASSWORD", "test-password")
	t.Setenv("IBKR_GATEWAY_MANAGER_PORT", port)
	t.Setenv("IBKR_GATEWAY_PUBLIC_DOMAIN", "ibkr.example.test")
	path := filepath.Join(t.TempDir(), "config.json")
	cfg, err := appconfig.LoadOrCreate(path)
	if err != nil {
		t.Fatal(err)
	}
	s, err := NewRegistry(path, cfg, func(c gateway.Config) Gateway { return &fakeGateway{baseURL: c.GatewayURL} })
	if err != nil {
		t.Fatal(err)
	}
	if err := s.StartProxyListeners(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.ShutdownProxyListeners(context.Background()) })
	client := &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{Proxy: nil}}
	t.Cleanup(client.CloseIdleConnections)
	var cookie *http.Cookie
	call := func(method, host, path, body string, want int) ([]byte, []*http.Cookie) {
		t.Helper()
		r, err := http.NewRequest(method, "http://127.0.0.1:"+port+path, strings.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		r.Host = host
		r.Header.Set("Origin", "https://"+host)
		r.Header.Set("Content-Type", "application/json")
		if cookie != nil && host == "manager.ibkr.example.test" {
			r.AddCookie(cookie)
		}
		resp, err := client.Do(r)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		data, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Fatal(err)
		}
		if resp.StatusCode != want {
			t.Fatalf("%s %s%s: %d, want %d: %s", method, host, path, resp.StatusCode, want, data)
		}
		return data, resp.Cookies()
	}
	call("GET", "platform-healthcheck", "/healthz", "", 200)
	call("GET", "manager.ibkr.example.test", "/manager/", "", 200)
	_, cookies := call("POST", "manager.ibkr.example.test", "/auth/v1/session", `{"username":"admin","password":"test-password"}`, 200)
	if len(cookies) != 1 || !cookies[0].Secure || !cookies[0].HttpOnly {
		t.Fatal("HTTPS login did not issue a secure session cookie")
	}
	cookie = cookies[0]
	call("PUT", "manager.ibkr.example.test", "/management/v1/config", `{"gateways":{"primary":{"use_global_defaults":true,"gateway_port":5680,"auto_start":false}}}`, 200)
	data, _ := call("POST", "manager.ibkr.example.test", "/management/v1/gateways/primary/login-ticket", "", 201)
	var ticket struct {
		URL string `json:"url"`
	}
	if err := json.Unmarshal(data, &ticket); err != nil || !strings.HasPrefix(ticket.URL, "https://primary.ibkr.example.test/_manager/login?ticket=") {
		t.Fatalf("incorrect instance login URL: %s", data)
	}
	call("GET", "primary.ibkr.example.test", "/v1/api/iserver/auth/status", "", 401)
	call("GET", "unknown.ibkr.example.test", "/manager/", "", 421)
	call("PUT", "manager.ibkr.example.test", "/management/v1/config", `{"public_domain":"changed.example.test","gateways":{}}`, 400)
	call("PUT", "manager.ibkr.example.test", "/management/v1/config", `{"port":1,"gateways":{}}`, 400)
}
