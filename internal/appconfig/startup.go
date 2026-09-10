package appconfig

import (
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"
)

var dnsLabelPattern = regexp.MustCompile(`^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$`)

// applyPublicDeployment expands the four-setting public deployment contract.
// Recompute on validation so saved derived values never pin an old domain/port.
// The existing advanced environment overrides are applied afterwards.
func (c *Config) applyPublicDeployment() error {
	if value := strings.TrimSpace(os.Getenv("IBKR_GATEWAY_PUBLIC_DOMAIN")); value != "" {
		c.PublicDomain = value
	}
	if value := strings.TrimSpace(os.Getenv("IBKR_GATEWAY_MANAGER_PORT")); value != "" {
		port, err := strconv.Atoi(value)
		if err != nil || port < 1 || port > 65535 {
			return fmt.Errorf("IBKR_GATEWAY_MANAGER_PORT must be an integer between 1 and 65535")
		}
		c.Port = port
	}
	if c.Port < 0 || c.Port > 65535 {
		return fmt.Errorf("port must be between 1 and 65535, or omitted for the default")
	}
	c.PublicDomain = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(c.PublicDomain), "."))
	if c.PublicDomain != "" {
		labels := strings.Split(c.PublicDomain, ".")
		// Reserve room for a full 63-character instance label and the dot.
		if len(c.PublicDomain) > 189 || len(labels) < 2 || net.ParseIP(c.PublicDomain) != nil {
			return fmt.Errorf("public_domain must be a base DNS domain such as ibkr.example.com, without protocol, port or path")
		}
		for _, label := range labels {
			if !dnsLabelPattern.MatchString(label) {
				return fmt.Errorf("public_domain must be a base DNS domain such as ibkr.example.com, without protocol, port or path")
			}
		}
		if c.PublicDomain == "localhost" || strings.HasSuffix(c.PublicDomain, ".localhost") {
			return fmt.Errorf("public_domain requires a public DNS domain; use local_tls for localhost")
		}
		if c.Port == 0 {
			c.Port = 8088
		}
	}
	if c.Port != 0 {
		oldListen := c.ListenAddr
		_, oldPort, _ := net.SplitHostPort(oldListen)
		oldPublic, _ := url.Parse(c.PublicURL)
		localHTTP := oldPublic != nil && oldPublic.Scheme == "http" && oldPublic.Hostname() == "127.0.0.1" && oldPublic.Port() == oldPort
		c.ListenAddr = net.JoinHostPort("0.0.0.0", strconv.Itoa(c.Port))
		if c.SharedProxyListenAddr != "" {
			c.SharedProxyListenAddr = c.ListenAddr
		}
		if c.PublicURL == "" || c.PublicURL == "http://127.0.0.1:8088" || c.PublicURL == "http://"+oldListen || localHTTP {
			c.PublicURL = "http://127.0.0.1:" + strconv.Itoa(c.Port)
		}
	}
	if c.PublicDomain != "" {
		c.PublicURL = "https://manager." + c.PublicDomain
		c.ProxyPublicURLTemplate = "https://{id}." + c.PublicDomain
		c.SharedProxyListenAddr = c.ListenAddr
		c.ProxyTLSTerminated = true
		c.LocalTLS = false
		c.ProxyTLSCertFile, c.ProxyTLSKeyFile = "", ""
	}
	return nil
}

// applyStartupDefaults fills omitted deployment settings before validation.
// Presence matters: an explicit empty listener or false TLS termination value
// must survive saving and restarting, rather than opting back into defaults.
func (c *Config) applyStartupDefaults(data []byte) error {
	var explicit struct {
		SharedListen  *string `json:"shared_proxy_listen_addr"`
		TLSTerminated *bool   `json:"proxy_tls_terminated"`
	}
	if len(data) > 0 {
		if err := json.Unmarshal(data, &explicit); err != nil {
			return fmt.Errorf("decode deployment settings: %w", err)
		}
	}
	value := func(name, fallback string) string {
		if override := strings.TrimSpace(os.Getenv(name)); override != "" {
			return override
		}
		return strings.TrimSpace(fallback)
	}
	localTLS := c.LocalTLS
	if override := value("IBKR_GATEWAY_LOCAL_TLS", ""); override != "" {
		var err error
		localTLS, err = strconv.ParseBool(override)
		if err != nil {
			return fmt.Errorf("IBKR_GATEWAY_LOCAL_TLS must be a boolean: %w", err)
		}
	}
	public, _ := url.Parse(value("IBKR_GATEWAY_MANAGER_PUBLIC_URL", c.PublicURL))
	if explicit.SharedListen == nil && c.SharedProxyListenAddr == "" && !localTLS && public != nil && public.Scheme == "https" {
		c.SharedProxyListenAddr = "0.0.0.0:8088"
	}
	if explicit.TLSTerminated == nil && value("IBKR_GATEWAY_PROXY_TLS_TERMINATED", "") == "" {
		c.ProxyTLSTerminated = value("IBKR_GATEWAY_SHARED_LISTEN", c.SharedProxyListenAddr) != "" && !localTLS &&
			value("IBKR_GATEWAY_PROXY_TLS_CERT", c.ProxyTLSCertFile) == "" &&
			value("IBKR_GATEWAY_PROXY_TLS_KEY", c.ProxyTLSKeyFile) == ""
	}
	return nil
}
