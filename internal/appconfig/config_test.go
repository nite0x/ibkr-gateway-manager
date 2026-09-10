package appconfig

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/nite0x/ibkr-gateway-manager/gateway"
)

func TestLoadOrCreateRoundTrip(t *testing.T) {
	t.Setenv("IBKR_GATEWAY_MANAGER_USERNAME", "admin")
	t.Setenv("IBKR_GATEWAY_MANAGER_PASSWORD", "test-password")
	path := filepath.Join(t.TempDir(), "config.json")
	cfg, err := LoadOrCreate(path)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Gateways == nil || len(cfg.Gateways) != 0 || cfg.ListenAddr != "127.0.0.1:8088" {
		t.Fatalf("unexpected defaults: %#v", cfg)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("config mode = %o", info.Mode().Perm())
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), `"gateways"`) || strings.Contains(string(data), `"gateway":`) {
		t.Fatalf("unexpected persisted schema: %s", data)
	}
	loaded, err := LoadOrCreate(path)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.Gateways == nil || len(loaded.Gateways) != 0 {
		t.Fatal("empty installation created an instance on reload")
	}
}

func TestLegacySingleGatewayMigrates(t *testing.T) {
	baseDir := t.TempDir()
	path := filepath.Join(baseDir, "config.json")
	legacy := map[string]any{
		"listen_addr": "127.0.0.1:8088",
		"public_url":  "http://127.0.0.1:8088",
		"auto_start":  false,
		"username":    "admin", "password": "test-password",
		"gateway": map[string]any{
			"gateway_dir": "legacy", "gateway_port": 5681,
			"gateway_url": "https://127.0.0.1:5681",
		},
	}
	data, err := json.Marshal(legacy)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := LoadOrCreate(path)
	if err != nil {
		t.Fatal(err)
	}
	instance := cfg.Gateways[DefaultGatewayID]
	if instance.AutoStart || instance.GatewayPort != 5681 || instance.GatewayDir != filepath.Join(baseDir, "legacy") {
		t.Fatalf("unexpected migrated instance: %#v", instance)
	}
	if cfg.Gateway != nil || cfg.AutoStart != nil {
		t.Fatal("deprecated fields were not cleared")
	}
}

func TestGatewaysRequireUniquePortsAndDirectories(t *testing.T) {
	baseDir := t.TempDir()
	cfg := testDefault(baseDir)
	first := cfg.Gateways[DefaultGatewayID]
	cfg.Gateways["paper"] = GatewayInstance{Config: gateway.Config{
		GatewayDir: filepath.Join(baseDir, "paper"), GatewayPort: first.GatewayPort,
		GatewayURL: "https://127.0.0.1:5680",
	}}
	if err := cfg.Validate(baseDir); err == nil {
		t.Fatal("expected duplicate port to fail")
	}

	cfg = testDefault(baseDir)
	first = cfg.Gateways[DefaultGatewayID]
	first.UseGlobalDefaults = false
	cfg.Gateways[DefaultGatewayID] = first
	cfg.Gateways["paper"] = GatewayInstance{Config: gateway.Config{
		GatewayDir: first.GatewayDir, GatewayPort: 5681,
		GatewayURL: "https://127.0.0.1:5681",
	}}
	if err := cfg.Validate(baseDir); err == nil {
		t.Fatal("expected duplicate directory to fail")
	}
}

func TestRemoteListenRequiresCredentials(t *testing.T) {
	cfg := testDefault(t.TempDir())
	cfg.ListenAddr = "0.0.0.0:8088"
	cfg.APIToken = ""
	cfg.Password = ""
	if err := cfg.Validate(t.TempDir()); err == nil {
		t.Fatal("missing password accepted")
	}
	t.Setenv("IBKR_GATEWAY_MANAGER_PASSWORD", "secret")
	if err := cfg.Validate(t.TempDir()); err != nil {
		t.Fatal(err)
	}
}

func TestDedicatedProxyConfigurationIsNormalizedAndIsolated(t *testing.T) {
	baseDir := t.TempDir()
	cfg := testDefault(baseDir)
	primary := cfg.Gateways[DefaultGatewayID]
	primary.UseGlobalDefaults = false
	primary.ProxyListenAddr = "127.0.0.1:18081"
	cfg.Gateways[DefaultGatewayID] = primary
	cfg.Gateways["paper"] = GatewayInstance{
		Config: gateway.Config{
			GatewayDir: filepath.Join(baseDir, "paper"), GatewayPort: 5681,
			GatewayURL: "https://127.0.0.1:5681",
		},
		ProxyListenAddr: "127.0.0.1:18082",
		ProxyPublicURL:  "http://127.0.0.1:18082/",
	}
	if err := cfg.Validate(baseDir); err != nil {
		t.Fatal(err)
	}
	if got := cfg.Gateways[DefaultGatewayID].ProxyPublicURL; got != "http://127.0.0.1:18081" {
		t.Fatalf("derived proxy URL = %q", got)
	}
	if got := cfg.Gateways["paper"].ProxyPublicURL; got != "http://127.0.0.1:18082" {
		t.Fatalf("normalized proxy URL = %q", got)
	}
}

func TestDedicatedProxyRejectsPortCollisionsAndUnsafeRemoteHTTP(t *testing.T) {
	baseDir := t.TempDir()
	cfg := testDefault(baseDir)
	primary := cfg.Gateways[DefaultGatewayID]
	primary.UseGlobalDefaults = false
	primary.ProxyListenAddr = "127.0.0.1:5680"
	primary.ProxyPublicURL = "http://127.0.0.1:5680"
	cfg.Gateways[DefaultGatewayID] = primary
	if err := cfg.Validate(baseDir); err == nil || !strings.Contains(err.Error(), "same port") {
		t.Fatalf("gateway/proxy collision error = %v", err)
	}

	cfg = testDefault(baseDir)
	primary = cfg.Gateways[DefaultGatewayID]
	primary.UseGlobalDefaults = false
	primary.ProxyListenAddr = "0.0.0.0:18081"
	primary.ProxyPublicURL = "http://gateway.example.com:18081"
	primary.ProxyToken = "primary-key"
	cfg.Gateways[DefaultGatewayID] = primary
	if err := cfg.Validate(baseDir); err == nil || !strings.Contains(err.Error(), "HTTPS") {
		t.Fatalf("unsafe remote HTTP error = %v", err)
	}
}

func TestGlobalDefaultsDerivePerInstancePathsAndOrigins(t *testing.T) {
	baseDir := t.TempDir()
	cfg := testDefault(baseDir)
	cfg.GatewayRootDir = "runtime"
	cfg.ProxyListenHost = "127.0.0.1"
	cfg.ProxyPublicURLTemplate = "https://{id}.ibkr.example.com"
	cfg.ProxyTLSCertFile = "cert.pem"
	cfg.ProxyTLSKeyFile = "key.pem"
	cfg.DownloadProxy = "http://127.0.0.1:7890"
	cfg.Gateways["paper"] = GatewayInstance{
		UseGlobalDefaults: true,
		ProxyPort:         18082,
		Config: gateway.Config{
			GatewayPort:      5681,
			GatewayLifecycle: gateway.LifecycleManaged,
		},
	}
	if err := cfg.Validate(baseDir); err != nil {
		t.Fatal(err)
	}
	paper := cfg.Gateways["paper"]
	if paper.GatewayDir != filepath.Join(baseDir, "runtime", "shared") {
		t.Fatalf("gateway dir = %q", paper.GatewayDir)
	}
	if paper.GatewayURL != "https://localhost:5681" || paper.ProxyListenAddr != "127.0.0.1:18082" {
		t.Fatalf("derived private endpoints = %#v", paper)
	}
	if paper.ProxyPublicURL != "https://paper.ibkr.example.com" || paper.DownloadProxy != cfg.DownloadProxy {
		t.Fatalf("derived shared defaults = %#v", paper)
	}
}

func TestSharedProxyRequiresUniqueHTTPSHostsOnItsPort(t *testing.T) {
	baseDir := t.TempDir()
	cfg := testDefault(baseDir)
	cfg.SharedProxyListenAddr = "127.0.0.1:443"
	cfg.PublicURL = "https://manager.localhost"
	cfg.ProxyPublicURLTemplate = "https://{id}.localhost"
	cfg.ProxyTLSCertFile = "proxy.crt"
	cfg.ProxyTLSKeyFile = "proxy.key"
	cfg.Gateways["paper"] = GatewayInstance{
		UseGlobalDefaults: true,
		ProxyPort:         18082,
		Config: gateway.Config{
			GatewayPort: 5681,
		},
	}
	if err := cfg.Validate(baseDir); err != nil {
		t.Fatal(err)
	}
	if cfg.Gateways[DefaultGatewayID].ProxyPublicURL != "https://primary.localhost" ||
		cfg.Gateways["paper"].ProxyPublicURL != "https://paper.localhost" {
		t.Fatalf("shared proxy origins = %#v", cfg.Gateways)
	}

	duplicate := cfg
	duplicate.ProxyPublicURLTemplate = "https://localhost"
	if err := duplicate.Validate(baseDir); err == nil || !strings.Contains(err.Error(), "same shared proxy hostname") {
		t.Fatalf("duplicate shared hostname error = %v", err)
	}

	wrongPort := cfg
	wrongPort.ProxyPublicURLTemplate = "https://{id}.localhost:8443"
	if err := wrongPort.Validate(baseDir); err == nil || !strings.Contains(err.Error(), "must match shared proxy port") {
		t.Fatalf("shared proxy port error = %v", err)
	}

	managerCollision := cfg
	managerCollision.ProxyPublicURLTemplate = "https://manager.localhost"
	if err := managerCollision.Validate(baseDir); err == nil || !strings.Contains(err.Error(), "and manager use the same shared proxy hostname") {
		t.Fatalf("manager shared hostname collision error = %v", err)
	}

	managerHTTP := cfg
	managerHTTP.PublicURL = "http://manager.localhost"
	if err := managerHTTP.Validate(baseDir); err == nil || !strings.Contains(err.Error(), "public_url must use HTTPS") {
		t.Fatalf("manager shared HTTP origin error = %v", err)
	}

	managerWrongPort := cfg
	managerWrongPort.PublicURL = "https://manager.localhost:8443"
	if err := managerWrongPort.Validate(baseDir); err == nil || !strings.Contains(err.Error(), "public_url port must match shared proxy port") {
		t.Fatalf("manager shared port error = %v", err)
	}
}

func TestTLSTerminatedSharedProxyAllowsExternalHTTPSOnInternalPort(t *testing.T) {
	baseDir := t.TempDir()
	cfg := testDefault(baseDir)
	cfg.ListenAddr = "0.0.0.0:8088"
	cfg.PublicURL = "https://manager.ibkr.example.com"
	cfg.APIToken = "manager-secret"
	cfg.SharedProxyListenAddr = "0.0.0.0:8088"
	cfg.ProxyPublicURLTemplate = "https://{id}.ibkr.example.com"
	primary := cfg.Gateways[DefaultGatewayID]
	primary.ProxyToken = "primary-secret"
	cfg.Gateways[DefaultGatewayID] = primary
	cfg.ProxyTLSTerminated = true
	cfg.ProxyTLSCertFile = ""
	cfg.ProxyTLSKeyFile = ""

	if err := cfg.Validate(baseDir); err != nil {
		t.Fatalf("validate TLS-terminated shared proxy: %v", err)
	}
	if got := cfg.Gateways[DefaultGatewayID].ProxyPublicURL; got != "https://primary.ibkr.example.com" {
		t.Fatalf("proxy public URL = %q", got)
	}
}

func TestSharedProxyRemovesPerInstancePorts(t *testing.T) {
	for _, inherit := range []bool{true, false} {
		t.Run(fmt.Sprintf("inherit=%t", inherit), func(t *testing.T) {
			base := t.TempDir()
			cfg := testDefault(base)
			cfg.PublicURL = "https://manager.localhost:8443"
			cfg.SharedProxyListenAddr = "127.0.0.1:8443"
			cfg.ProxyPublicURLTemplate = "https://{id}.localhost:8443"
			cfg.ProxyTLSCertFile, cfg.ProxyTLSKeyFile = "cert.pem", "key.pem"
			cfg.ProxyListenHost = "unused:invalid"
			for i, id := range []string{"primary", "paper"} {
				cfg.Gateways[id] = GatewayInstance{
					InstallationMode: "shared", UseGlobalDefaults: inherit,
					Config: gateway.Config{GatewayPort: 5680 + i},
					// Obsolete values must not trigger validation or port conflicts.
					ProxyPort: -1, ProxyListenAddr: "unused:invalid",
					ProxyPublicURL: "https://" + id + ".localhost:8443",
				}
			}
			if err := cfg.Validate(base); err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(base, "config.json")
			if err := Save(path, cfg); err != nil {
				t.Fatal(err)
			}
			data, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			for _, field := range []string{`"proxy_port"`, `"proxy_listen_addr"`, `"proxy_listen_host"`} {
				if strings.Contains(string(data), field) {
					t.Fatalf("unused %s persisted", field)
				}
			}
			loaded, err := LoadOrCreate(path)
			if err != nil {
				t.Fatal(err)
			}
			for id, instance := range loaded.Gateways {
				if instance.ProxyPort != 0 || instance.ProxyListenAddr != "" || instance.ProxyPublicURL != "https://"+id+".localhost:8443" {
					t.Fatalf("unexpected shared proxy configuration: %#v", instance)
				}
			}
			loaded.ProxyPublicURLTemplate = "https://{id}.localhost:{port}"
			if err := loaded.Validate(base); err == nil || !strings.Contains(err.Error(), "cannot use {port}") {
				t.Fatalf("shared template must not depend on instance ports: %v", err)
			}
		})
	}
}

func TestSharedProxyValidatesItsActualListener(t *testing.T) {
	base := t.TempDir()
	cfg := testDefault(base)
	cfg.PublicURL = "https://manager.localhost"
	cfg.APIToken = "manager-token"
	cfg.SharedProxyListenAddr = "0.0.0.0:8081"
	cfg.ProxyTLSTerminated = true
	cfg.ProxyPublicURLTemplate = "https://{id}.localhost"
	if err := cfg.Validate(base); err == nil || !strings.Contains(err.Error(), "proxy_token is required") {
		t.Fatalf("remote shared listener must require a proxy token: %v", err)
	}
}

func TestRailwayProxyEnvironmentOverrides(t *testing.T) {
	baseDir := t.TempDir()
	cfg := testDefault(baseDir)
	cfg.APIToken = "manager-secret"
	t.Setenv("IBKR_GATEWAY_MANAGER_LISTEN", "0.0.0.0:8088")
	t.Setenv("IBKR_GATEWAY_MANAGER_PUBLIC_URL", "https://manager.ibkr.example.com")
	t.Setenv("IBKR_GATEWAY_SHARED_LISTEN", "0.0.0.0:8088")
	t.Setenv("IBKR_GATEWAY_PROXY_PUBLIC_URL_TEMPLATE", "https://{id}.ibkr.example.com")
	t.Setenv("IBKR_GATEWAY_PROXY_TLS_TERMINATED", "true")
	t.Setenv("IBKR_GATEWAY_PROXY_TOKENS", `{"primary":"primary-secret"}`)

	if err := cfg.Validate(baseDir); err != nil {
		t.Fatalf("validate Railway environment: %v", err)
	}
	if !cfg.ProxyTLSTerminated || cfg.SharedProxyListenAddr != "0.0.0.0:8088" {
		t.Fatalf("Railway environment not applied: %#v", cfg)
	}
	if cfg.Gateways[DefaultGatewayID].ProxyToken != "primary-secret" {
		t.Fatal("proxy token environment was not applied")
	}
}

func TestLegacyInstancesKeepExplicitValues(t *testing.T) {
	baseDir := t.TempDir()
	cfg := testDefault(baseDir)
	cfg.GatewayRootDir = filepath.Join(baseDir, "new-root")
	cfg.ProxyPublicURLTemplate = "https://{id}.new.example.com"
	cfg.Gateways[DefaultGatewayID] = GatewayInstance{
		Config: gateway.Config{
			GatewayDir:       filepath.Join(baseDir, "legacy"),
			GatewayPort:      5688,
			GatewayURL:       "https://127.0.0.1:5688",
			GatewayProxyHost: "https://legacy.example.com",
			GatewayAllowIPs:  []string{"127.0.0.1"},
		},
		ProxyListenAddr: "127.0.0.1:18888",
		ProxyPublicURL:  "http://127.0.0.1:18888",
	}
	if err := cfg.Validate(baseDir); err != nil {
		t.Fatal(err)
	}
	instance := cfg.Gateways[DefaultGatewayID]
	if instance.UseGlobalDefaults || instance.GatewayDir != filepath.Join(baseDir, "legacy") || instance.ProxyPublicURL != "http://127.0.0.1:18888" {
		t.Fatalf("legacy values were overwritten: %#v", instance)
	}
	if instance.ProxyPort != 18888 {
		t.Fatalf("legacy proxy port was not inferred: %d", instance.ProxyPort)
	}
}

func TestSharedDefaultsKeepConfigsStateAndSubdomainsIndependent(t *testing.T) {
	base := t.TempDir()
	cfg := testDefault(base)
	cfg.ProxyPublicURLTemplate = "https://{id}.ibkr.example.com"
	cfg.ProxyTLSCertFile = "proxy.crt"
	cfg.ProxyTLSKeyFile = "proxy.key"
	cfg.Gateways["paper"] = GatewayInstance{UseGlobalDefaults: true, ProxyPort: 18082, Config: gateway.Config{GatewayPort: 5682}}
	if err := cfg.Validate(base); err != nil {
		t.Fatal(err)
	}
	primary, paper := cfg.Gateways["primary"], cfg.Gateways["paper"]
	if primary.GatewayDir != paper.GatewayDir || primary.GatewayConfigFile == paper.GatewayConfigFile || primary.GatewayStateDir == paper.GatewayStateDir {
		t.Fatalf("shared configuration not isolated: %#v %#v", primary, paper)
	}
	if primary.ProxyPublicURL != "https://primary.ibkr.example.com" || paper.ProxyPublicURL != "https://paper.ibkr.example.com" {
		t.Fatal("instance subdomains changed")
	}
	// Explicit users may also point two configs at the same installation.
	paper.UseGlobalDefaults = false
	paper.GatewayStateDir = ""
	cfg.Gateways["paper"] = paper
	if err := cfg.Validate(base); err != nil {
		t.Fatal(err)
	}
	paper = cfg.Gateways["paper"]
	paper.GatewayConfigFile = primary.GatewayConfigFile
	cfg.Gateways["paper"] = paper
	if err := cfg.Validate(base); err == nil {
		t.Fatal("expected duplicate config to fail")
	}
}

func TestSharedDefaultsReuseLegacyInstallWithoutMovingExistingInstance(t *testing.T) {
	base := t.TempDir()
	legacy := filepath.Join(base, "gateways", "paper")
	if err := os.MkdirAll(filepath.Join(legacy, "root"), 0o700); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"conf.yaml", "run.jar"} {
		if err := os.WriteFile(filepath.Join(legacy, "root", name), []byte("existing"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	cfg := testDefault(base)
	cfg.Gateways["paper"] = GatewayInstance{UseGlobalDefaults: true, ProxyPort: 18082, Config: gateway.Config{GatewayPort: 5682}}
	if err := cfg.Validate(base); err != nil {
		t.Fatal(err)
	}
	if cfg.SharedGatewayDir != legacy || cfg.Gateways["primary"].GatewayDir != legacy {
		t.Fatal("existing installation was not reused")
	}
	paper := cfg.Gateways["paper"]
	if paper.GatewayStateDir != legacy || paper.GatewayConfigFile != "root/conf.yaml" {
		t.Fatal("legacy process identity changed")
	}
	path := filepath.Join(base, "config.json")
	if err := Save(path, cfg); err != nil {
		t.Fatal(err)
	}
	loaded, err := LoadOrCreate(path)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.SharedGatewayDir != legacy || loaded.Gateways["paper"].GatewayConfigFile != "root/conf.yaml" {
		t.Fatal("shared choice did not survive reload")
	}
}

func TestInstallationModeAndNetworkInheritanceAreIndependent(t *testing.T) {
	for _, mode := range []string{"shared", "independent"} {
		for _, inherit := range []bool{true, false} {
			t.Run(fmt.Sprintf("%s/inherit=%t", mode, inherit), func(t *testing.T) {
				base := t.TempDir()
				cfg := testDefault(base)
				cfg.BundledGatewayDir = filepath.Join(base, "global-template")
				instance := GatewayInstance{
					InstallationMode: mode, UseGlobalDefaults: inherit, ProxyPort: 18082,
					Config: gateway.Config{GatewayPort: 5682, BundledGatewayDir: "version-template"},
				}
				cfg.Gateways["version-test"] = instance
				if err := cfg.Validate(base); err != nil {
					t.Fatal(err)
				}
				instance = cfg.Gateways["version-test"]
				if mode == "shared" {
					if instance.GatewayDir != cfg.SharedGatewayDir || instance.GatewayConfigFile != "root/conf-version-test.yaml" || instance.BundledGatewayDir != cfg.BundledGatewayDir {
						t.Fatalf("shared paths = %#v", instance)
					}
				} else if instance.GatewayDir != filepath.Join(base, "gateways", "version-test") || instance.GatewayConfigFile != "root/conf.yaml" || instance.BundledGatewayDir != filepath.Join(base, "version-template") {
					t.Fatalf("independent paths or template overwritten = %#v", instance)
				}
				if inherit && instance.ProxyListenAddr != "127.0.0.1:18082" {
					t.Fatalf("network defaults not applied: %#v", instance)
				}
				path := filepath.Join(base, "config.json")
				if err := Save(path, cfg); err != nil {
					t.Fatal(err)
				}
				loaded, err := LoadOrCreate(path)
				if err != nil {
					t.Fatal(err)
				}
				again := loaded.Gateways["version-test"]
				if again.InstallationMode != mode || again.GatewayDir != instance.GatewayDir || again.GatewayConfigFile != instance.GatewayConfigFile || again.GatewayStateDir != instance.GatewayStateDir || again.BundledGatewayDir != instance.BundledGatewayDir {
					t.Fatalf("installation changed after reload: %#v", again)
				}
			})
		}
	}
}

func TestIndependentInstallationCannotBeShared(t *testing.T) {
	for _, collision := range []string{"global", "instance", "symlink", "invalid-mode"} {
		t.Run(collision, func(t *testing.T) {
			base := t.TempDir()
			cfg := testDefault(base)
			cfg.SharedGatewayDir = filepath.Join(base, "shared")
			dir := cfg.SharedGatewayDir
			if collision == "instance" {
				dir = filepath.Join(base, "separate")
				primary := cfg.Gateways["primary"]
				primary.UseGlobalDefaults = false
				primary.GatewayDir = dir
				cfg.Gateways["primary"] = primary
			}
			if collision == "symlink" {
				if err := os.MkdirAll(dir, 0o700); err != nil {
					t.Fatal(err)
				}
				dir = filepath.Join(base, "alias")
				if err := os.Symlink(cfg.SharedGatewayDir, dir); err != nil {
					t.Fatal(err)
				}
			}
			mode := "independent"
			if collision == "invalid-mode" {
				mode = "download"
			}
			cfg.Gateways["other"] = GatewayInstance{InstallationMode: mode, UseGlobalDefaults: true, ProxyPort: 18082, Config: gateway.Config{GatewayDir: dir, GatewayPort: 5682, GatewayConfigFile: "root/conf-other.yaml"}}
			if err := cfg.Validate(base); err == nil {
				t.Fatal("expected invalid installation choice to fail")
			}
		})
	}
}

func TestSharedDiscoverySkipsIndependentVersions(t *testing.T) {
	base := t.TempDir()
	cfg := testDefault(base)
	dir := filepath.Join(cfg.GatewayRootDir, "older-version")
	if err := os.MkdirAll(filepath.Join(dir, "root"), 0o700); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"conf.yaml", "run.jar"} {
		if err := os.WriteFile(filepath.Join(dir, "root", name), []byte("existing"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	cfg.Gateways["older-version"] = GatewayInstance{InstallationMode: "independent", UseGlobalDefaults: true, ProxyPort: 18082, Config: gateway.Config{GatewayPort: 5682}}
	if err := cfg.Validate(base); err != nil {
		t.Fatal(err)
	}
	if cfg.SharedGatewayDir == dir {
		t.Fatal("independent version was adopted as the shared installation")
	}
}

func testDefault(base string) Config {
	cfg := Default(base)
	cfg.Username, cfg.Password = "admin", "test-password"
	cfg.Gateways[DefaultGatewayID] = GatewayInstance{
		UseGlobalDefaults: true, AutoStart: true, ProxyPort: 18081,
		Config: gateway.Config{GatewayPort: 5680, GatewayLifecycle: "managed"},
	}
	return cfg
}
