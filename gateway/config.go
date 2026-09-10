package gateway

import (
	"fmt"
	"net"
	"net/url"
	"path/filepath"
	"strings"
)

const (
	LifecycleManaged    = "managed"
	LifecyclePersistent = "persistent"
)

// Config describes one locally managed IBKR Client Portal Gateway process.
// GatewayURL must be a loopback origin because the daemon is the only public
// boundary allowed to expose the Gateway.
type Config struct {
	GatewayDir        string   `json:"gateway_dir"`
	GatewayConfigFile string   `json:"gateway_config_file,omitempty"`
	GatewayStateDir   string   `json:"gateway_state_dir,omitempty"`
	BundledGatewayDir string   `json:"bundled_gateway_dir,omitempty"`
	GatewayPort       int      `json:"gateway_port"`
	GatewayURL        string   `json:"gateway_url"`
	GatewayLifecycle  string   `json:"gateway_lifecycle"`
	DownloadProxy     string   `json:"download_proxy,omitempty"`
	GatewayProxyHost  string   `json:"gateway_proxy_host"`
	GatewayAllowIPs   []string `json:"gateway_allow_ips"`
}

func NormalizeLifecycle(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case LifecyclePersistent:
		return LifecyclePersistent
	default:
		return LifecycleManaged
	}
}

// NormalizeAndValidate fills safe defaults and rejects configurations that
// would let the raw Client Portal Gateway escape the daemon boundary.
func (c *Config) NormalizeAndValidate(baseDir string) error {
	if strings.TrimSpace(c.GatewayDir) == "" {
		c.GatewayDir = filepath.Join(baseDir, "gateway")
	} else if !filepath.IsAbs(c.GatewayDir) {
		c.GatewayDir = filepath.Join(baseDir, c.GatewayDir)
	}
	if c.BundledGatewayDir != "" && !filepath.IsAbs(c.BundledGatewayDir) {
		c.BundledGatewayDir = filepath.Join(baseDir, c.BundledGatewayDir)
	}
	if c.GatewayConfigFile == "" {
		c.GatewayConfigFile = "root/conf.yaml"
	}
	c.GatewayConfigFile = filepath.ToSlash(filepath.Clean(c.GatewayConfigFile))
	if filepath.Dir(c.GatewayConfigFile) != "root" || !strings.HasSuffix(c.GatewayConfigFile, ".yaml") {
		return fmt.Errorf("gateway_config_file must be a YAML file inside root/")
	}
	if c.GatewayStateDir == "" {
		c.GatewayStateDir = c.GatewayDir
		if c.GatewayConfigFile != "root/conf.yaml" {
			c.GatewayStateDir = filepath.Join(c.GatewayDir+".instances", strings.TrimSuffix(filepath.Base(c.GatewayConfigFile), ".yaml"))
		}
	} else if !filepath.IsAbs(c.GatewayStateDir) {
		c.GatewayStateDir = filepath.Join(baseDir, c.GatewayStateDir)
	}
	if c.GatewayPort == 0 {
		c.GatewayPort = 5680
	}
	if c.GatewayPort < 1 || c.GatewayPort > 65535 {
		return fmt.Errorf("gateway port must be between 1 and 65535")
	}
	if strings.TrimSpace(c.GatewayURL) == "" {
		c.GatewayURL = fmt.Sprintf("https://127.0.0.1:%d", c.GatewayPort)
	}
	c.GatewayURL = strings.TrimSuffix(strings.TrimRight(c.GatewayURL, "/"), "/v1/api")
	u, err := url.Parse(c.GatewayURL)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return fmt.Errorf("gateway URL must be an HTTP(S) origin")
	}
	if u.User != nil || u.RawQuery != "" || u.Fragment != "" || (u.Path != "" && u.Path != "/") {
		return fmt.Errorf("gateway URL must be an origin without credentials, path, query, or fragment")
	}
	host := strings.Trim(strings.ToLower(u.Hostname()), "[]")
	ip := net.ParseIP(host)
	if host != "localhost" && (ip == nil || !ip.IsLoopback()) {
		return fmt.Errorf("gateway URL must use a loopback host")
	}
	if u.Port() != fmt.Sprintf("%d", c.GatewayPort) {
		return fmt.Errorf("gateway URL port must match gateway_port")
	}
	c.GatewayLifecycle = NormalizeLifecycle(c.GatewayLifecycle)
	if strings.TrimSpace(c.GatewayProxyHost) == "" {
		c.GatewayProxyHost = "https://api.ibkr.com"
	}
	if len(c.GatewayAllowIPs) == 0 {
		c.GatewayAllowIPs = []string{"127.0.0.1"}
	}
	return nil
}

func (c Config) stateDir() string {
	if c.GatewayStateDir != "" {
		return c.GatewayStateDir
	}
	return c.GatewayDir
}

func (c Config) configFile() string {
	if c.GatewayConfigFile != "" {
		return c.GatewayConfigFile
	}
	return "root/conf.yaml"
}
