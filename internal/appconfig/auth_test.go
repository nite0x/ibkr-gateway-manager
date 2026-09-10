package appconfig

import (
	"path/filepath"
	"testing"
)

func TestStartupAuthConfiguration(t *testing.T) {
	cfg := Default(t.TempDir())
	if err := cfg.ValidateAuth(); err == nil {
		t.Fatal("missing credentials accepted")
	}
	cfg.Username = "admin"
	cfg.Password = "password"
	cfg.SessionTTLMinutes = 0
	if err := cfg.ValidateAuth(); err != nil || cfg.SessionTTLMinutes != 30 {
		t.Fatalf("default expiry: %v", err)
	}
	for _, ttl := range []int{-1, 525601} {
		cfg.SessionTTLMinutes = ttl
		if err := cfg.ValidateAuth(); err == nil {
			t.Fatalf("invalid ttl %d", ttl)
		}
	}
	t.Setenv("IBKR_GATEWAY_MANAGER_USERNAME", "operator")
	t.Setenv("IBKR_GATEWAY_MANAGER_PASSWORD", "password with spaces ")
	t.Setenv("IBKR_GATEWAY_MANAGER_SESSION_TTL_MINUTES", "45")
	if err := cfg.ValidateAuth(); err != nil {
		t.Fatal(err)
	}
	if cfg.Username != "operator" || cfg.Password != "password with spaces " || cfg.SessionTTLMinutes != 45 {
		t.Fatal("startup overrides not applied")
	}
	for _, ttl := range []string{"-1", "0", "1.5", "invalid", ""} {
		t.Setenv("IBKR_GATEWAY_MANAGER_SESSION_TTL_MINUTES", ttl)
		if err := cfg.ValidateAuth(); err == nil {
			t.Fatalf("invalid env ttl %q", ttl)
		}
	}
}

func TestStartupRejectsOldUnauthenticatedConfig(t *testing.T) {
	cfg := Default(t.TempDir())
	cfg.APIToken = "old-token"
	path := filepath.Join(t.TempDir(), "config.json")
	if err := Save(path, cfg); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadOrCreate(path); err == nil {
		t.Fatal("token-only config accepted without credentials")
	}
}
