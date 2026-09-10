package appconfig

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestStartupDeploymentModes(t *testing.T) {
	for _, name := range []string{
		"IBKR_GATEWAY_MANAGER_LISTEN", "IBKR_GATEWAY_MANAGER_PUBLIC_URL", "IBKR_GATEWAY_SHARED_LISTEN",
		"IBKR_GATEWAY_PROXY_PUBLIC_URL_TEMPLATE", "IBKR_GATEWAY_PROXY_TLS_TERMINATED",
		"IBKR_GATEWAY_LOCAL_TLS", "IBKR_GATEWAY_PROXY_TLS_CERT", "IBKR_GATEWAY_PROXY_TLS_KEY",
	} {
		t.Setenv(name, "")
	}
	for _, tc := range []struct {
		name       string
		fields     map[string]any
		env        map[string]string
		listen     string
		terminated bool
		errorText  string
	}{
		{name: "public HTTPS", listen: "0.0.0.0:8088", terminated: true},
		{name: "custom shared listener", env: map[string]string{"IBKR_GATEWAY_SHARED_LISTEN": "127.0.0.1:9088"}, listen: "127.0.0.1:9088", terminated: true},
		{name: "local HTTP", fields: map[string]any{"public_url": "http://127.0.0.1:8088"}},
		{name: "local certificates", fields: map[string]any{"local_tls": true, "public_url": "https://manager.localhost:8088", "proxy_public_url_template": "https://{id}.localhost:8088"}, listen: "127.0.0.1:8088"},
		{name: "explicit certificates", fields: map[string]any{"public_url": "https://manager.example.test:8088", "proxy_tls_cert_file": "cert.pem", "proxy_tls_key_file": "key.pem"}, listen: "0.0.0.0:8088"},
		{name: "environment certificates", env: map[string]string{"IBKR_GATEWAY_MANAGER_PUBLIC_URL": "https://manager.example.test:8088", "IBKR_GATEWAY_PROXY_TLS_CERT": "cert.pem", "IBKR_GATEWAY_PROXY_TLS_KEY": "key.pem"}, listen: "0.0.0.0:8088"},
		{name: "explicit dedicated listener", fields: map[string]any{"shared_proxy_listen_addr": "", "proxy_tls_terminated": false}},
		{name: "explicit false requires certificates", fields: map[string]any{"proxy_tls_terminated": false}, errorText: "proxy_tls_cert_file and proxy_tls_key_file are required"},
		{name: "environment false requires certificates", env: map[string]string{"IBKR_GATEWAY_PROXY_TLS_TERMINATED": "false"}, errorText: "proxy_tls_cert_file and proxy_tls_key_file are required"},
		{name: "environment overrides false", fields: map[string]any{"proxy_tls_terminated": false}, env: map[string]string{"IBKR_GATEWAY_PROXY_TLS_TERMINATED": "true"}, listen: "0.0.0.0:8088", terminated: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			for name, value := range tc.env {
				t.Setenv(name, value)
			}
			fields := map[string]any{
				"username": "admin", "password": "test-password",
				"public_url":                "https://manager.example.test",
				"proxy_public_url_template": "https://{id}.example.test",
				"gateways":                  map[string]any{},
			}
			for key, value := range tc.fields {
				fields[key] = value
			}
			data, err := json.Marshal(fields)
			if err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(t.TempDir(), "config.json")
			if err := os.WriteFile(path, data, 0o600); err != nil {
				t.Fatal(err)
			}
			for range 2 {
				cfg, err := LoadOrCreate(path)
				if tc.errorText != "" {
					if err == nil || !strings.Contains(err.Error(), tc.errorText) {
						t.Fatalf("expected %q, got %v", tc.errorText, err)
					}
					return
				}
				if err != nil {
					t.Fatal(err)
				}
				if cfg.SharedProxyListenAddr != tc.listen || cfg.ProxyTLSTerminated != tc.terminated {
					t.Fatalf("listen=%q terminated=%v", cfg.SharedProxyListenAddr, cfg.ProxyTLSTerminated)
				}
				if err := Save(path, cfg); err != nil {
					t.Fatal(err)
				}
			}
		})
	}
}
