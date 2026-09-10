package appconfig

import (
	"path/filepath"
	"testing"
)

func TestFourSettingPublicDeployment(t *testing.T) {
	t.Setenv("IBKR_GATEWAY_MANAGER_USERNAME", "admin")
	t.Setenv("IBKR_GATEWAY_MANAGER_PASSWORD", "test-password")
	t.Setenv("IBKR_GATEWAY_MANAGER_PORT", "9088")
	t.Setenv("IBKR_GATEWAY_PUBLIC_DOMAIN", "IBKR.Example.Test.")
	path := filepath.Join(t.TempDir(), "config.json")
	cfg, err := LoadOrCreate(path)
	if err != nil {
		t.Fatal(err)
	}
	check := func(cfg Config, domain, port string) {
		t.Helper()
		if cfg.PublicDomain != domain || cfg.PublicURL != "https://manager."+domain ||
			cfg.ProxyPublicURLTemplate != "https://{id}."+domain ||
			cfg.ListenAddr != "0.0.0.0:"+port || cfg.SharedProxyListenAddr != cfg.ListenAddr ||
			!cfg.ProxyTLSTerminated || cfg.LocalTLS || cfg.SessionTTLMinutes != 30 {
			t.Fatalf("unexpected derived settings: domain=%q public=%q template=%q listen=%q shared=%q terminated=%v local=%v ttl=%d",
				cfg.PublicDomain, cfg.PublicURL, cfg.ProxyPublicURLTemplate, cfg.ListenAddr, cfg.SharedProxyListenAddr, cfg.ProxyTLSTerminated, cfg.LocalTLS, cfg.SessionTTLMinutes)
		}
	}
	check(cfg, "ibkr.example.test", "9088")
	if len(cfg.Gateways) != 0 {
		t.Fatal("startup created an instance")
	}
	cfg.Gateways["primary"] = GatewayInstance{UseGlobalDefaults: true, ProxyToken: "existing-instance-token"}
	if err := cfg.Validate(filepath.Dir(path)); err != nil {
		t.Fatal(err)
	}
	if err := Save(path, cfg); err != nil {
		t.Fatal(err)
	}
	// Removing env overrides leaves the same complete configuration on disk.
	t.Setenv("IBKR_GATEWAY_MANAGER_PORT", "")
	t.Setenv("IBKR_GATEWAY_PUBLIC_DOMAIN", "")
	reloaded, err := LoadOrCreate(path)
	if err != nil {
		t.Fatal(err)
	}
	check(reloaded, "ibkr.example.test", "9088")
	previous := reloaded.Gateways["primary"]
	if previous.ProxyPublicURL != "https://primary.ibkr.example.test" {
		t.Fatalf("unexpected instance origin: %s", previous.ProxyPublicURL)
	}
	// The four settings take precedence over previously saved derived values.
	t.Setenv("IBKR_GATEWAY_MANAGER_PORT", "9188")
	t.Setenv("IBKR_GATEWAY_PUBLIC_DOMAIN", "new.example.test")
	changed, err := LoadOrCreate(path)
	if err != nil {
		t.Fatal(err)
	}
	check(changed, "new.example.test", "9188")
	instance := changed.Gateways["primary"]
	if instance.ProxyPublicURL != "https://primary.new.example.test" || instance.ProxyToken != previous.ProxyToken || instance.GatewayStateDir != previous.GatewayStateDir {
		t.Fatal("domain change did not preserve instance identity while updating its origin")
	}
}

func TestPublicDeploymentInputValidation(t *testing.T) {
	for _, domain := range []string{"https://ibkr.example.test", "ibkr.example.test:443", "ibkr.example.test/path", "*.example.test", "a..test", "a_b.test", "-bad.test", "127.0.0.1", "foo.localhost"} {
		t.Run(domain, func(t *testing.T) {
			cfg := Default(t.TempDir())
			cfg.PublicDomain = domain
			if err := cfg.applyPublicDeployment(); err == nil {
				t.Fatalf("invalid domain accepted: %q", domain)
			}
		})
	}
	for _, port := range []string{"0", "-1", "65536", "8088.5", "http"} {
		t.Run(port, func(t *testing.T) {
			t.Setenv("IBKR_GATEWAY_MANAGER_PORT", port)
			cfg := Default(t.TempDir())
			if err := cfg.applyPublicDeployment(); err == nil {
				t.Fatalf("invalid port accepted: %q", port)
			}
		})
	}
}

func TestPublicDeploymentDefaultPortAndInstanceLabels(t *testing.T) {
	cfg := testDefault(t.TempDir())
	cfg.PublicDomain = "ibkr.example.test"
	instance := cfg.Gateways["primary"]
	instance.ProxyToken = "test-instance-token"
	cfg.Gateways["primary"] = instance
	if err := cfg.Validate(t.TempDir()); err != nil {
		t.Fatal(err)
	}
	if cfg.Port != 8088 || cfg.SharedProxyListenAddr != "0.0.0.0:8088" {
		t.Fatal("missing default port")
	}
	for _, id := range []string{"bad_name", "nested.name", "manager"} {
		t.Run(id, func(t *testing.T) {
			invalid := cfg.Clone()
			invalid.Gateways = map[string]GatewayInstance{id: cfg.Gateways["primary"]}
			if err := invalid.Validate(t.TempDir()); err == nil {
				t.Fatalf("invalid or reserved instance label accepted: %q", id)
			}
		})
	}
}

func TestPortOnlyLocalStartupAndRestart(t *testing.T) {
	t.Setenv("IBKR_GATEWAY_MANAGER_USERNAME", "admin")
	t.Setenv("IBKR_GATEWAY_MANAGER_PASSWORD", "test-password")
	t.Setenv("IBKR_GATEWAY_MANAGER_PORT", "9088")
	path := filepath.Join(t.TempDir(), "config.json")
	for _, port := range []string{"9088", "9188"} {
		t.Setenv("IBKR_GATEWAY_MANAGER_PORT", port)
		cfg, err := LoadOrCreate(path)
		if err != nil {
			t.Fatal(err)
		}
		if cfg.ListenAddr != "0.0.0.0:"+port || cfg.PublicURL != "http://127.0.0.1:"+port || cfg.SharedProxyListenAddr != "" {
			t.Fatal("local port override was not applied consistently")
		}
	}
}
