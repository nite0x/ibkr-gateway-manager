package appconfig

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/nite0x/ibkr-gateway-manager/gateway"
)

const DefaultGatewayID = "primary"

var gatewayIDPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`)

// GatewayInstance describes one independently managed Gateway. Embedding the
// Gateway config keeps the JSON representation flat and easy to edit.
type GatewayInstance struct {
	gateway.Config
	UseGlobalDefaults bool   `json:"use_global_defaults,omitempty"`
	InstallationMode  string `json:"installation_mode,omitempty"`
	AutoStart         bool   `json:"auto_start"`
	ProxyPort         int    `json:"proxy_port,omitempty"`
	ProxyListenAddr   string `json:"proxy_listen_addr,omitempty"`
	ProxyPublicURL    string `json:"proxy_public_url,omitempty"`
	ProxyToken        string `json:"proxy_token,omitempty"`
}

type Config struct {
	Port                   int                        `json:"port,omitempty"`
	PublicDomain           string                     `json:"public_domain,omitempty"`
	ListenAddr             string                     `json:"listen_addr"`
	PublicURL              string                     `json:"public_url"`
	Username               string                     `json:"username"`
	Password               string                     `json:"password,omitempty"`
	SessionTTLMinutes      int                        `json:"session_ttl_minutes"`
	APIToken               string                     `json:"api_token,omitempty"`
	SharedGatewayDir       string                     `json:"shared_gateway_dir,omitempty"`
	GatewayRootDir         string                     `json:"gateway_root_dir,omitempty"`
	BundledGatewayDir      string                     `json:"bundled_gateway_dir,omitempty"`
	DownloadProxy          string                     `json:"download_proxy,omitempty"`
	GatewayProxyHost       string                     `json:"gateway_proxy_host,omitempty"`
	GatewayAllowIPs        []string                   `json:"gateway_allow_ips,omitempty"`
	ProxyListenHost        string                     `json:"proxy_listen_host,omitempty"`
	ProxyPublicURLTemplate string                     `json:"proxy_public_url_template,omitempty"`
	SharedProxyListenAddr  string                     `json:"shared_proxy_listen_addr"`
	ProxyTLSTerminated     bool                       `json:"proxy_tls_terminated"`
	LocalTLS               bool                       `json:"local_tls,omitempty"`
	ProxyTLSCertFile       string                     `json:"proxy_tls_cert_file,omitempty"`
	ProxyTLSKeyFile        string                     `json:"proxy_tls_key_file,omitempty"`
	Gateways               map[string]GatewayInstance `json:"gateways"`

	// Deprecated single-Gateway fields are accepted on load and removed when
	// the configuration is next saved.
	AutoStart *bool           `json:"auto_start,omitempty"`
	Gateway   *gateway.Config `json:"gateway,omitempty"`
}

func Default(baseDir string) Config {
	return Config{
		SessionTTLMinutes:      30,
		ListenAddr:             "127.0.0.1:8088",
		PublicURL:              "http://127.0.0.1:8088",
		GatewayRootDir:         filepath.Join(baseDir, "gateways"),
		GatewayProxyHost:       "https://api.ibkr.com",
		GatewayAllowIPs:        []string{"127.0.0.1"},
		ProxyListenHost:        "127.0.0.1",
		ProxyPublicURLTemplate: "http://127.0.0.1:{port}",
		// Installation and credentials belong to user-created instances.
		Gateways: map[string]GatewayInstance{},
	}
}

func LoadOrCreate(path string) (Config, error) {
	baseDir := filepath.Dir(path)
	cfg := Config{}
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		cfg = Default(baseDir)
		if err := cfg.applyStartupDefaults(nil); err != nil {
			return Config{}, err
		}
		if err := cfg.Validate(baseDir); err != nil {
			return Config{}, err
		}
		if err := Save(path, cfg); err != nil {
			return Config{}, err
		}
		return cfg, nil
	}
	if err != nil {
		return Config{}, err
	}
	if err := json.Unmarshal(data, &cfg); err != nil {
		return Config{}, fmt.Errorf("decode config: %w", err)
	}
	if err := cfg.applyStartupDefaults(data); err != nil {
		return Config{}, err
	}
	if err := cfg.Validate(baseDir); err != nil {
		return Config{}, err
	}
	// Persist generated local instance tokens and normalized local origins once
	// validated, including when upgrading an existing configuration.
	if cfg.LocalTLS {
		if err := Save(path, cfg); err != nil {
			return Config{}, err
		}
	}
	return cfg, nil
}

func Save(path string, cfg Config) error {
	pending, err := PrepareSave(path, cfg)
	if err != nil {
		return err
	}
	defer pending.Abort()
	return pending.Commit()
}

// PendingSave holds a fully written and synced configuration before publication.
type PendingSave struct{ temporary, path string }

func (p *PendingSave) Commit() error { return os.Rename(p.temporary, p.path) }
func (p *PendingSave) Abort()        { _ = os.Remove(p.temporary) }

func PrepareSave(path string, cfg Config) (_ *PendingSave, resultErr error) {
	if info, err := os.Stat(path); err == nil && info.IsDir() {
		return nil, fmt.Errorf("config path is a directory: %s", path)
	} else if err != nil && !os.IsNotExist(err) {
		return nil, err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, err
	}
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return nil, err
	}
	data = append(data, '\n')
	temporary, err := os.CreateTemp(filepath.Dir(path), ".config-*.json")
	if err != nil {
		return nil, err
	}
	temporaryPath := temporary.Name()
	defer func() {
		if resultErr != nil {
			_ = os.Remove(temporaryPath)
		}
	}()
	if err := temporary.Chmod(0o600); err != nil {
		_ = temporary.Close()
		return nil, err
	}
	if _, err := temporary.Write(data); err != nil {
		_ = temporary.Close()
		return nil, err
	}
	if err := temporary.Sync(); err != nil {
		_ = temporary.Close()
		return nil, err
	}
	if err := temporary.Close(); err != nil {
		return nil, err
	}
	return &PendingSave{temporary: temporaryPath, path: path}, nil
}

func (c *Config) Validate(baseDir string) error {
	if err := c.ValidateAuth(); err != nil {
		return err
	}
	if err := c.applyPublicDeployment(); err != nil {
		return err
	}
	if value := strings.TrimSpace(os.Getenv("IBKR_GATEWAY_MANAGER_LISTEN")); value != "" {
		c.ListenAddr = value
	}
	if value := strings.TrimSpace(os.Getenv("IBKR_GATEWAY_MANAGER_PUBLIC_URL")); value != "" {
		c.PublicURL = value
	}
	if value := strings.TrimSpace(os.Getenv("IBKR_GATEWAY_SHARED_LISTEN")); value != "" {
		c.SharedProxyListenAddr = value
	}
	if value := strings.TrimSpace(os.Getenv("IBKR_GATEWAY_PROXY_PUBLIC_URL_TEMPLATE")); value != "" {
		c.ProxyPublicURLTemplate = value
	}
	if value := strings.TrimSpace(os.Getenv("IBKR_GATEWAY_PROXY_TLS_TERMINATED")); value != "" {
		terminated, err := strconv.ParseBool(value)
		if err != nil {
			return fmt.Errorf("IBKR_GATEWAY_PROXY_TLS_TERMINATED must be a boolean: %w", err)
		}
		c.ProxyTLSTerminated = terminated
	}
	c.ListenAddr = strings.TrimSpace(c.ListenAddr)
	if c.ListenAddr == "" {
		c.ListenAddr = "127.0.0.1:8088"
	}
	_, _, err := net.SplitHostPort(c.ListenAddr)
	if err != nil {
		return fmt.Errorf("listen_addr must be host:port: %w", err)
	}
	if err := c.configureLocalTLS(); err != nil {
		return err
	}
	c.PublicURL = strings.TrimRight(strings.TrimSpace(c.PublicURL), "/")
	if c.PublicURL == "" {
		c.PublicURL = "http://" + c.ListenAddr
	}
	public, err := url.Parse(c.PublicURL)
	if err != nil || (public.Scheme != "http" && public.Scheme != "https") || public.Host == "" {
		return fmt.Errorf("public_url must be an HTTP(S) origin")
	}
	if public.User != nil || public.RawQuery != "" || public.Fragment != "" || (public.Path != "" && public.Path != "/") {
		return fmt.Errorf("public_url must be an origin without credentials, path, query, or fragment")
	}
	if value := strings.TrimSpace(os.Getenv("IBKR_GATEWAY_PROXY_TLS_CERT")); value != "" {
		c.ProxyTLSCertFile = value
	}
	if value := strings.TrimSpace(os.Getenv("IBKR_GATEWAY_PROXY_TLS_KEY")); value != "" {
		c.ProxyTLSKeyFile = value
	}
	c.ProxyTLSCertFile = resolveOptionalPath(baseDir, c.ProxyTLSCertFile)
	c.ProxyTLSKeyFile = resolveOptionalPath(baseDir, c.ProxyTLSKeyFile)
	if c.LocalTLS && (c.ProxyTLSTerminated || c.ProxyTLSCertFile != "" || c.ProxyTLSKeyFile != "") {
		return fmt.Errorf("local_tls cannot be combined with external TLS termination or explicit certificate files")
	}
	if (c.ProxyTLSCertFile == "") != (c.ProxyTLSKeyFile == "") {
		return fmt.Errorf("proxy_tls_cert_file and proxy_tls_key_file must be configured together")
	}
	if err := c.normalizeGlobalDefaults(baseDir); err != nil {
		return err
	}
	sharedProxyPort := 0
	sharedProxyHosts := make(map[string]string, len(c.Gateways)+1)
	if c.SharedProxyListenAddr != "" {
		sharedHost, sharedPortValue, err := net.SplitHostPort(c.SharedProxyListenAddr)
		if err != nil {
			return fmt.Errorf("shared_proxy_listen_addr must be host:port: %w", err)
		}
		if strings.TrimSpace(sharedHost) == "" {
			return fmt.Errorf("shared_proxy_listen_addr must include a host")
		}
		sharedProxyPort, err = net.LookupPort("tcp", sharedPortValue)
		if err != nil || sharedProxyPort < 1 || sharedProxyPort > 65535 {
			return fmt.Errorf("shared proxy listen port must be between 1 and 65535")
		}
		if !c.LocalTLS && !c.ProxyTLSTerminated && c.ProxyTLSCertFile == "" {
			return fmt.Errorf("proxy_tls_cert_file and proxy_tls_key_file are required for the shared HTTPS proxy")
		}
		if public.Scheme != "https" {
			return fmt.Errorf("public_url must use HTTPS when the shared proxy is enabled")
		}
		if !c.ProxyTLSTerminated && publicOriginPort(public) != sharedProxyPort {
			return fmt.Errorf("public_url port must match shared proxy port %d", sharedProxyPort)
		}
		sharedProxyHosts[strings.ToLower(strings.TrimSuffix(public.Hostname(), "."))] = "manager"
	}

	if len(c.Gateways) > 0 && c.Gateway != nil {
		return fmt.Errorf("configure gateways or deprecated gateway, not both")
	}
	if len(c.Gateways) == 0 {
		if c.Gateway != nil {
			autoStart := true
			if c.AutoStart != nil {
				autoStart = *c.AutoStart
			}
			c.Gateways = map[string]GatewayInstance{
				DefaultGatewayID: {Config: *c.Gateway, AutoStart: autoStart},
			}
		} else {
			c.Gateways = map[string]GatewayInstance{}
		}
	}
	c.resolveSharedGatewayDir(baseDir)
	c.Gateway = nil
	c.AutoStart = nil
	proxyTokens := map[string]string{}
	if value := strings.TrimSpace(os.Getenv("IBKR_GATEWAY_PROXY_TOKENS")); value != "" {
		if err := json.Unmarshal([]byte(value), &proxyTokens); err != nil {
			return fmt.Errorf("IBKR_GATEWAY_PROXY_TOKENS must be a JSON object of gateway IDs to tokens: %w", err)
		}
	}

	ports := make(map[int]string, len(c.Gateways))
	proxyPorts := make(map[int]string, len(c.Gateways))
	directories := make(map[string]string, len(c.Gateways))
	configs := make(map[string]string, len(c.Gateways))
	installations := make(map[string]string, len(c.Gateways))
	requiresProxyTLS := false
	for id, instance := range c.Gateways {
		if token, ok := proxyTokens[id]; ok {
			instance.ProxyToken = strings.TrimSpace(token)
		}
		if !gatewayIDPattern.MatchString(id) || id == "." || id == ".." {
			return fmt.Errorf("gateway ID %q must match %s", id, gatewayIDPattern.String())
		}
		if c.PublicDomain != "" && instance.UseGlobalDefaults && !dnsLabelPattern.MatchString(id) {
			return fmt.Errorf("gateway ID %q must be a DNS label for public_domain", id)
		}
		if c.LocalTLS {
			if err := c.configureLocalInstance(id, &instance); err != nil {
				return err
			}
		}
		if sharedProxyPort != 0 {
			// Accept legacy fields on load, but never retain unused listeners in
			// the effective configuration or the next saved configuration.
			instance.ProxyPort = 0
			instance.ProxyListenAddr = ""
		}
		if instance.UseGlobalDefaults {
			if err := c.applyGlobalDefaults(id, &instance); err != nil {
				return fmt.Errorf("gateway %q: %w", id, err)
			}
		} else if instance.ProxyPort == 0 && instance.ProxyListenAddr != "" {
			_, portValue, err := net.SplitHostPort(strings.TrimSpace(instance.ProxyListenAddr))
			if err == nil {
				instance.ProxyPort, _ = net.LookupPort("tcp", portValue)
			}
		}
		if err := c.applyInstallationMode(id, &instance, baseDir); err != nil {
			return fmt.Errorf("gateway %q: %w", id, err)
		}
		if err := instance.Config.NormalizeAndValidate(baseDir); err != nil {
			return fmt.Errorf("gateway %q: %w", id, err)
		}
		programDir := canonicalDirectory(instance.GatewayDir)
		if instance.InstallationMode == "independent" && programDir == canonicalDirectory(c.SharedGatewayDir) {
			return fmt.Errorf("gateway %q: independent installation must not use shared_gateway_dir", id)
		}
		if other, exists := installations[programDir]; exists {
			if instance.InstallationMode == "independent" || c.Gateways[other].InstallationMode == "independent" {
				return fmt.Errorf("gateways %q and %q cannot share an independent installation", other, id)
			}
		}
		installations[programDir] = id
		if other, exists := ports[instance.GatewayPort]; exists {
			return fmt.Errorf("gateways %q and %q use the same port %d", other, id, instance.GatewayPort)
		}
		directory := filepath.Clean(instance.GatewayStateDir)
		if resolved, err := filepath.EvalSymlinks(directory); err == nil {
			directory = filepath.Clean(resolved)
		}
		if other, exists := directories[directory]; exists {
			return fmt.Errorf("gateways %q and %q use the same directory %s", other, id, directory)
		}
		configPath := filepath.Join(instance.GatewayDir, instance.GatewayConfigFile)
		if resolved, err := filepath.EvalSymlinks(instance.GatewayDir); err == nil {
			configPath = filepath.Join(resolved, instance.GatewayConfigFile)
		}
		if other, exists := configs[configPath]; exists {
			return fmt.Errorf("gateways %q and %q use the same configuration %s", other, id, configPath)
		}
		configs[configPath] = id
		instance.ProxyListenAddr = strings.TrimSpace(instance.ProxyListenAddr)
		instance.ProxyPublicURL = strings.TrimRight(strings.TrimSpace(instance.ProxyPublicURL), "/")
		instance.ProxyToken = strings.TrimSpace(instance.ProxyToken)
		if sharedProxyPort == 0 && instance.ProxyListenAddr == "" && instance.ProxyPublicURL != "" {
			return fmt.Errorf("gateway %q: proxy_listen_addr is required with proxy_public_url", id)
		}
		if sharedProxyPort != 0 || instance.ProxyListenAddr != "" {
			listenAddr := instance.ProxyListenAddr
			if sharedProxyPort != 0 {
				listenAddr = c.SharedProxyListenAddr
			}
			proxyHost, proxyPortValue, err := net.SplitHostPort(listenAddr)
			if err != nil {
				return fmt.Errorf("gateway %q: proxy listener must be host:port: %w", id, err)
			}
			proxyPort, err := net.LookupPort("tcp", proxyPortValue)
			if err != nil || proxyPort < 1 || proxyPort > 65535 {
				return fmt.Errorf("gateway %q: proxy listen port must be between 1 and 65535", id)
			}
			if instance.ProxyPublicURL == "" {
				if sharedProxyPort != 0 {
					return fmt.Errorf("gateway %q: proxy_public_url is required for the shared proxy", id)
				}
				proxyIP := net.ParseIP(strings.Trim(proxyHost, "[]"))
				if !strings.EqualFold(proxyHost, "localhost") && (proxyIP == nil || !proxyIP.IsLoopback()) {
					return fmt.Errorf("gateway %q: proxy_public_url is required for a non-loopback proxy listener", id)
				}
				instance.ProxyPublicURL = "http://" + instance.ProxyListenAddr
			}
			proxyPublic, err := url.Parse(instance.ProxyPublicURL)
			if err != nil || (proxyPublic.Scheme != "http" && proxyPublic.Scheme != "https") || proxyPublic.Host == "" {
				return fmt.Errorf("gateway %q: proxy_public_url must be an HTTP(S) origin", id)
			}
			if c.LocalTLS {
				if err := validateLocalOrigin(instance.ProxyPublicURL); err != nil {
					return fmt.Errorf("gateway %q: %w", id, err)
				}
			}
			if proxyPublic.User != nil || proxyPublic.RawQuery != "" || proxyPublic.Fragment != "" || (proxyPublic.Path != "" && proxyPublic.Path != "/") {
				return fmt.Errorf("gateway %q: proxy_public_url must be an origin without credentials, path, query, or fragment", id)
			}
			proxyIP := net.ParseIP(strings.Trim(proxyHost, "[]"))
			proxyIsLoopback := strings.EqualFold(proxyHost, "localhost") || (proxyIP != nil && proxyIP.IsLoopback())
			if !proxyIsLoopback && instance.ProxyToken == "" {
				return fmt.Errorf("gateway %q: proxy_token is required for a non-loopback proxy listener", id)
			}
			if !proxyIsLoopback && proxyPublic.Scheme != "https" {
				return fmt.Errorf("gateway %q: a non-loopback proxy listener requires an HTTPS proxy_public_url", id)
			}
			if sharedProxyPort != 0 {
				if proxyPublic.Scheme != "https" {
					return fmt.Errorf("gateway %q: the shared proxy requires an HTTPS proxy_public_url", id)
				}
				if !c.ProxyTLSTerminated && publicOriginPort(proxyPublic) != sharedProxyPort {
					return fmt.Errorf("gateway %q: proxy_public_url port must match shared proxy port %d", id, sharedProxyPort)
				}
				publicHost := strings.ToLower(strings.TrimSuffix(proxyPublic.Hostname(), "."))
				if other, exists := sharedProxyHosts[publicHost]; exists {
					if other == "manager" {
						return fmt.Errorf("gateway %q and manager use the same shared proxy hostname %s", id, publicHost)
					}
					return fmt.Errorf("gateways %q and %q use the same shared proxy hostname %s", other, id, publicHost)
				}
				sharedProxyHosts[publicHost] = id
			}
			if sharedProxyPort == 0 {
				if other, exists := proxyPorts[proxyPort]; exists {
					return fmt.Errorf("gateway proxies %q and %q use the same port %d", other, id, proxyPort)
				}
				proxyPorts[proxyPort] = id
			}
			requiresProxyTLS = requiresProxyTLS || (proxyPublic.Scheme == "https" && (sharedProxyPort == 0 || !c.ProxyTLSTerminated))
		}
		ports[instance.GatewayPort] = id
		directories[directory] = id
		c.Gateways[id] = instance
	}
	for port, proxyID := range proxyPorts {
		if gatewayID, exists := ports[port]; exists {
			return fmt.Errorf("gateway proxy %q and gateway %q use the same port %d", proxyID, gatewayID, port)
		}
	}
	if gatewayID, exists := ports[sharedProxyPort]; sharedProxyPort != 0 && exists {
		return fmt.Errorf("shared proxy and gateway %q use the same port %d", gatewayID, sharedProxyPort)
	}
	_, managerPortValue, _ := net.SplitHostPort(c.ListenAddr)
	managerPort, _ := net.LookupPort("tcp", managerPortValue)
	if proxyID, exists := proxyPorts[managerPort]; exists {
		return fmt.Errorf("gateway proxy %q and manager use the same port %d", proxyID, managerPort)
	}
	if requiresProxyTLS && c.ProxyTLSCertFile == "" && !c.LocalTLS {
		return fmt.Errorf("proxy_tls_cert_file and proxy_tls_key_file are required for HTTPS gateway proxies")
	}
	return nil
}

func resolveOptionalPath(baseDir, value string) string {
	value = strings.TrimSpace(value)
	if value == "" || filepath.IsAbs(value) {
		return value
	}
	return filepath.Join(baseDir, value)
}

func (c *Config) normalizeGlobalDefaults(baseDir string) error {
	// The image provides a read-only template, never a live installation. An
	// explicit per-installation choice takes precedence over the image default.
	if c.BundledGatewayDir == "" {
		c.BundledGatewayDir = strings.TrimSpace(os.Getenv("IBKR_GATEWAY_BUNDLED_DIR"))
	}
	c.GatewayRootDir = strings.TrimSpace(c.GatewayRootDir)
	if c.GatewayRootDir == "" {
		c.GatewayRootDir = filepath.Join(baseDir, "gateways")
	} else if !filepath.IsAbs(c.GatewayRootDir) {
		c.GatewayRootDir = filepath.Join(baseDir, c.GatewayRootDir)
	}
	c.BundledGatewayDir = resolveOptionalPath(baseDir, c.BundledGatewayDir)
	c.DownloadProxy = strings.TrimSpace(c.DownloadProxy)
	c.GatewayProxyHost = strings.TrimRight(strings.TrimSpace(c.GatewayProxyHost), "/")
	if c.GatewayProxyHost == "" {
		c.GatewayProxyHost = "https://api.ibkr.com"
	}
	if len(c.GatewayAllowIPs) == 0 {
		c.GatewayAllowIPs = []string{"127.0.0.1"}
	}
	c.SharedProxyListenAddr = strings.TrimSpace(c.SharedProxyListenAddr)
	if c.SharedProxyListenAddr != "" {
		c.ProxyListenHost = ""
	} else {
		c.ProxyListenHost = strings.TrimSpace(c.ProxyListenHost)
		if c.ProxyListenHost == "" {
			c.ProxyListenHost = "127.0.0.1"
		}
		if strings.Contains(c.ProxyListenHost, ":") && net.ParseIP(strings.Trim(c.ProxyListenHost, "[]")) == nil {
			return fmt.Errorf("proxy_listen_host must be a host without a port")
		}
		c.ProxyListenHost = strings.Trim(c.ProxyListenHost, "[]")
	}
	c.ProxyPublicURLTemplate = strings.TrimRight(strings.TrimSpace(c.ProxyPublicURLTemplate), "/")
	if c.ProxyPublicURLTemplate == "" {
		c.ProxyPublicURLTemplate = "http://127.0.0.1:{port}"
		if c.SharedProxyListenAddr != "" {
			c.ProxyPublicURLTemplate = "https://{id}.localhost"
			public, _ := url.Parse(c.PublicURL)
			if public != nil && public.Port() != "" {
				c.ProxyPublicURLTemplate += ":" + public.Port()
			}
		}
	}
	if c.SharedProxyListenAddr != "" && strings.Contains(c.ProxyPublicURLTemplate, "{port}") {
		return fmt.Errorf("proxy_public_url_template cannot use {port} with the shared proxy; use {id} and the shared public origin port")
	}
	return validatePublicOrigin(expandProxyPublicURL(c.ProxyPublicURLTemplate, "example", 18081), "proxy_public_url_template")
}

func (c Config) applyGlobalDefaults(id string, instance *GatewayInstance) error {
	if instance.GatewayPort == 0 {
		instance.GatewayPort = 5680
	}
	if c.SharedProxyListenAddr == "" && (instance.ProxyPort < 1 || instance.ProxyPort > 65535) {
		return fmt.Errorf("proxy_port must be between 1 and 65535")
	}
	if instance.InstallationMode == "" {
		// Preserve existing installations and process identities on upgrade. New
		// instances always share the selected program and get only a new YAML file.
		legacyDir := instance.GatewayDir
		if legacyDir == "" {
			legacyDir = filepath.Join(c.GatewayRootDir, id)
		}
		legacy := instance.GatewayConfigFile == "root/conf.yaml"
		if instance.GatewayConfigFile == "" {
			_, confErr := os.Stat(filepath.Join(legacyDir, "root", "conf.yaml"))
			_, jarErr := os.Stat(filepath.Join(legacyDir, "root", "run.jar"))
			_, scriptErr := os.Stat(filepath.Join(legacyDir, "bin", "run.sh"))
			legacy = confErr == nil && (jarErr == nil || scriptErr == nil)
		}
		if legacy {
			instance.GatewayDir = legacyDir
			instance.GatewayConfigFile = "root/conf.yaml"
			instance.GatewayStateDir = legacyDir
		} else {
			instance.GatewayDir = c.SharedGatewayDir
			instance.GatewayConfigFile = "root/conf-" + id + ".yaml"
			instance.GatewayStateDir = filepath.Join(c.GatewayRootDir, ".instances", id)
		}
		instance.BundledGatewayDir = c.BundledGatewayDir
	}
	if instance.InstallationMode == "shared" {
		instance.BundledGatewayDir = c.BundledGatewayDir
	}
	// The Client Portal Gateway login application is documented and served on
	// the localhost origin. Keep that origin when proxying browser authentication:
	// the reverse proxy rewrites Host, Origin, and Referer to GatewayURL.
	instance.GatewayURL = fmt.Sprintf("https://localhost:%d", instance.GatewayPort)
	instance.DownloadProxy = c.DownloadProxy
	instance.GatewayProxyHost = c.GatewayProxyHost
	instance.GatewayAllowIPs = append([]string(nil), c.GatewayAllowIPs...)
	if c.SharedProxyListenAddr == "" {
		instance.ProxyListenAddr = net.JoinHostPort(c.ProxyListenHost, strconv.Itoa(instance.ProxyPort))
		instance.ProxyPublicURL = expandProxyPublicURL(c.ProxyPublicURLTemplate, id, instance.ProxyPort)
	} else {
		instance.ProxyPublicURL = strings.ReplaceAll(c.ProxyPublicURLTemplate, "{id}", id)
	}
	return nil
}

// Explicit installation choices are independent of network inheritance. An
// empty mode preserves the directory semantics of older configuration files.
func (c Config) applyInstallationMode(id string, instance *GatewayInstance, baseDir string) error {
	switch instance.InstallationMode {
	case "":
		return nil
	case "shared":
		if instance.GatewayDir != "" && canonicalDirectory(resolveOptionalPath(baseDir, instance.GatewayDir)) != canonicalDirectory(c.SharedGatewayDir) {
			instance.GatewayConfigFile = ""
			instance.GatewayStateDir = ""
		}
		instance.GatewayDir = c.SharedGatewayDir
		instance.BundledGatewayDir = c.BundledGatewayDir
		if instance.GatewayConfigFile == "" {
			instance.GatewayConfigFile = "root/conf-" + id + ".yaml"
		}
		if instance.GatewayStateDir == "" {
			instance.GatewayStateDir = filepath.Join(c.GatewayRootDir, ".instances", id)
		}
	case "independent":
		if strings.TrimSpace(instance.GatewayDir) == "" {
			instance.GatewayDir = filepath.Join(c.GatewayRootDir, id)
		}
	default:
		return fmt.Errorf("installation_mode must be shared or independent")
	}
	return nil
}

func canonicalDirectory(dir string) string {
	if resolved, err := filepath.EvalSymlinks(dir); err == nil {
		return filepath.Clean(resolved)
	}
	return filepath.Clean(dir)
}

func expandProxyPublicURL(template, id string, port int) string {
	result := strings.ReplaceAll(template, "{id}", id)
	return strings.ReplaceAll(result, "{port}", strconv.Itoa(port))
}

func validatePublicOrigin(value, field string) error {
	public, err := url.Parse(value)
	if err != nil || (public.Scheme != "http" && public.Scheme != "https") || public.Host == "" {
		return fmt.Errorf("%s must expand to an HTTP(S) origin", field)
	}
	if public.User != nil || public.RawQuery != "" || public.Fragment != "" || (public.Path != "" && public.Path != "/") {
		return fmt.Errorf("%s must expand to an origin without credentials, path, query, or fragment", field)
	}
	return nil
}

func publicOriginPort(public *url.URL) int {
	if value := public.Port(); value != "" {
		port, _ := net.LookupPort("tcp", value)
		return port
	}
	if strings.EqualFold(public.Scheme, "https") {
		return 443
	}
	return 80
}

// Persist the chosen installation so adding/removing IDs cannot move it.
// Existing installations are reused in place; no archive is downloaded again.
func (c *Config) resolveSharedGatewayDir(baseDir string) {
	if c.SharedGatewayDir != "" {
		c.SharedGatewayDir = resolveOptionalPath(baseDir, c.SharedGatewayDir)
		return
	}
	candidates := []string{filepath.Join(c.GatewayRootDir, "shared"), filepath.Join(c.GatewayRootDir, DefaultGatewayID)}
	entries, _ := os.ReadDir(c.GatewayRootDir)
	for _, entry := range entries {
		if entry.IsDir() && !strings.HasPrefix(entry.Name(), ".") && !strings.HasSuffix(entry.Name(), ".rollback") {
			candidates = append(candidates, filepath.Join(c.GatewayRootDir, entry.Name()))
		}
	}
	ids := make([]string, 0, len(c.Gateways))
	independentDirs := make(map[string]bool)
	for id := range c.Gateways {
		ids = append(ids, id)
		if instance := c.Gateways[id]; instance.InstallationMode == "independent" {
			dir := instance.GatewayDir
			if dir == "" {
				dir = filepath.Join(c.GatewayRootDir, id)
			}
			independentDirs[canonicalDirectory(resolveOptionalPath(baseDir, dir))] = true
		}
	}
	sort.Strings(ids)
	for _, id := range ids {
		if dir := c.Gateways[id].GatewayDir; dir != "" {
			candidates = append(candidates, resolveOptionalPath(baseDir, dir))
		}
	}
	for _, dir := range candidates {
		if independentDirs[canonicalDirectory(dir)] {
			continue
		}
		if _, err := os.Stat(filepath.Join(dir, "root", "conf.yaml")); err != nil {
			continue
		}
		for _, startup := range []string{"root/run.jar", "bin/run.sh"} {
			if _, err := os.Stat(filepath.Join(dir, startup)); err == nil {
				c.SharedGatewayDir = dir
				return
			}
		}
	}
	c.SharedGatewayDir = filepath.Join(c.GatewayRootDir, "shared")
}

// ValidateAuth applies startup credentials. API tokens are generated by the
// authenticated browser and persisted in the configuration, not overridden by env.
func (c *Config) ValidateAuth() error {
	if value, ok := os.LookupEnv("IBKR_GATEWAY_MANAGER_USERNAME"); ok {
		c.Username = value
	}
	if value, ok := os.LookupEnv("IBKR_GATEWAY_MANAGER_PASSWORD"); ok {
		c.Password = value
	}
	if value, ok := os.LookupEnv("IBKR_GATEWAY_MANAGER_SESSION_TTL_MINUTES"); ok {
		ttl, err := strconv.Atoi(value)
		if err != nil || ttl <= 0 {
			return errors.New("IBKR_GATEWAY_MANAGER_SESSION_TTL_MINUTES must be a positive integer")
		}
		c.SessionTTLMinutes = ttl
	}
	c.Username = strings.TrimSpace(c.Username)
	if c.Username == "" || strings.TrimSpace(c.Password) == "" {
		return errors.New("username and password are required in startup configuration")
	}
	if c.SessionTTLMinutes == 0 {
		c.SessionTTLMinutes = 30
	}
	if c.SessionTTLMinutes < 1 || c.SessionTTLMinutes > 525600 {
		return errors.New("session_ttl_minutes must be between 1 and 525600")
	}
	return nil
}
