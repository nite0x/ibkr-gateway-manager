package appconfig

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLocalTLSMigratesAndPersistsExistingConfig(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")
	cfg := testDefault(dir)
	if err := Save(path, cfg); err != nil {
		t.Fatal(err)
	}
	t.Setenv("IBKR_GATEWAY_LOCAL_TLS", "true")
	t.Setenv("IBKR_GATEWAY_MANAGER_LISTEN", "0.0.0.0:8088")
	loaded, err := LoadOrCreate(path)
	if err != nil {
		t.Fatal(err)
	}
	if !loaded.LocalTLS || loaded.SharedProxyListenAddr != "0.0.0.0:8088" || loaded.PublicURL != "https://manager.localhost:8088" {
		t.Fatalf("local defaults: %+v", loaded)
	}
	instance := loaded.Gateways["primary"]
	if instance.ProxyPublicURL != "https://primary.localhost:8088" || len(instance.ProxyToken) != 64 {
		t.Fatal("missing local origin or token")
	}
	second, err := LoadOrCreate(path)
	if err != nil {
		t.Fatal(err)
	}
	if second.Gateways["primary"].ProxyToken != instance.ProxyToken {
		t.Fatal("token changed on restart")
	}
	if _, err := os.Stat(filepath.Join(dir, "tls")); !os.IsNotExist(err) {
		t.Fatal("validation generated certificate files")
	}
}

func TestLocalTLSRejectsIncompatibleSettings(t *testing.T) {
	for name, mutate := range map[string]func(*Config){
		"external terminator":  func(c *Config) { c.ProxyTLSTerminated = true },
		"explicit certificate": func(c *Config) { c.ProxyTLSCertFile = "cert.pem"; c.ProxyTLSKeyFile = "key.pem" },
		"public domain":        func(c *Config) { c.PublicURL = "https://manager.example.com:8088" },
		"nested domain":        func(c *Config) { c.ProxyPublicURLTemplate = "https://{id}.ib.localhost:8088" },
		"uncovered instance": func(c *Config) {
			i := c.Gateways["primary"]
			i.UseGlobalDefaults = false
			i.ProxyPublicURL = "https://example.com:8088"
			c.Gateways["primary"] = i
		},
		"invalid instance label": func(c *Config) { c.Gateways["bad_name"] = c.Gateways["primary"]; delete(c.Gateways, "primary") },
	} {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			cfg := testDefault(dir)
			cfg.LocalTLS = true
			mutate(&cfg)
			if err := cfg.Validate(dir); err == nil {
				t.Fatal("incompatible configuration accepted")
			}
		})
	}
}

func TestLocalTLSKeepsExplicitTokenAndInstallation(t *testing.T) {
	dir := t.TempDir()
	cfg := testDefault(dir)
	cfg.LocalTLS = true
	i := cfg.Gateways["primary"]
	i.UseGlobalDefaults = false
	i.ProxyToken = "existing-token"
	i.ProxyPublicURL = "http://127.0.0.1:18081"
	i.GatewayDir = filepath.Join(dir, "existing")
	cfg.Gateways["primary"] = i
	if err := cfg.Validate(dir); err != nil {
		t.Fatal(err)
	}
	got := cfg.Gateways["primary"]
	if got.ProxyToken != i.ProxyToken || got.GatewayDir != i.GatewayDir || got.ProxyPublicURL != "https://primary.localhost:8088" {
		t.Fatalf("migration changed instance unexpectedly: %+v", got)
	}
}

func TestLocalTLSRequiresBoolean(t *testing.T) {
	t.Setenv("IBKR_GATEWAY_LOCAL_TLS", "perhaps")
	dir := t.TempDir()
	cfg := testDefault(dir)
	if err := cfg.Validate(dir); err == nil || !strings.Contains(err.Error(), "boolean") {
		t.Fatalf("got %v", err)
	}
}
