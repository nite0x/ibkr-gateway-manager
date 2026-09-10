package appconfig

import (
	"os"
	"path/filepath"
	"testing"
)

func TestFreshPublicDeploymentStaysEmpty(t *testing.T) {
	t.Setenv("IBKR_GATEWAY_MANAGER_USERNAME", "admin")
	t.Setenv("IBKR_GATEWAY_MANAGER_PASSWORD", "test-password")
	t.Setenv("IBKR_GATEWAY_MANAGER_LISTEN", "")
	t.Setenv("IBKR_GATEWAY_SHARED_LISTEN", "")
	t.Setenv("IBKR_GATEWAY_MANAGER_PUBLIC_URL", "https://manager.example.test")
	t.Setenv("IBKR_GATEWAY_PROXY_PUBLIC_URL_TEMPLATE", "https://{id}.example.test")
	t.Setenv("IBKR_GATEWAY_PROXY_TLS_TERMINATED", "")
	t.Setenv("IBKR_GATEWAY_PROXY_TOKENS", "")
	t.Setenv("IBKR_GATEWAY_BUNDLED_DIR", "/opt/ibkr-gateway")
	path := filepath.Join(t.TempDir(), "config.json")
	for range 2 {
		cfg, err := LoadOrCreate(path)
		if err != nil {
			t.Fatal(err)
		}
		if cfg.Gateways == nil || len(cfg.Gateways) != 0 || cfg.BundledGatewayDir != "/opt/ibkr-gateway" {
			t.Fatalf("unexpected empty deployment: %+v", cfg)
		}
		if cfg.SharedProxyListenAddr != "0.0.0.0:8088" || !cfg.ProxyTLSTerminated {
			t.Fatalf("missing public deployment defaults: %+v", cfg)
		}
		if _, err := os.Stat(cfg.GatewayRootDir); !os.IsNotExist(err) {
			t.Fatalf("empty deployment created runtime data: %v", err)
		}
	}
}

func TestImageBundleDefaultPreservesConfiguredTemplate(t *testing.T) {
	t.Setenv("IBKR_GATEWAY_BUNDLED_DIR", "/opt/ibkr-gateway")
	base := t.TempDir()
	cfg := testDefault(base)
	cfg.BundledGatewayDir = filepath.Join(base, "custom-release")
	if err := cfg.Validate(base); err != nil {
		t.Fatal(err)
	}
	if cfg.BundledGatewayDir != filepath.Join(base, "custom-release") {
		t.Fatal("image default replaced user template")
	}
}
