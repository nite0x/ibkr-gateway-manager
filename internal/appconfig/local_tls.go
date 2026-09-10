package appconfig

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net"
	"net/url"
	"os"
	"strconv"
	"strings"

	"github.com/nite0x/ibkr-gateway-manager/internal/localtls"
)

func (c *Config) configureLocalTLS() error {
	if value := strings.TrimSpace(os.Getenv("IBKR_GATEWAY_LOCAL_TLS")); value != "" {
		enabled, err := strconv.ParseBool(value)
		if err != nil {
			return fmt.Errorf("IBKR_GATEWAY_LOCAL_TLS must be a boolean: %w", err)
		}
		c.LocalTLS = enabled
	}
	if !c.LocalTLS {
		return nil
	}
	if c.SharedProxyListenAddr == "" {
		c.SharedProxyListenAddr = c.ListenAddr
	}
	_, port, err := net.SplitHostPort(c.SharedProxyListenAddr)
	if err != nil {
		return fmt.Errorf("shared_proxy_listen_addr: %w", err)
	}
	// Migrate the built-in HTTP defaults. Explicit non-local origins are never
	// silently replaced by localhost certificates.
	if c.PublicURL == "" || c.PublicURL == "http://127.0.0.1:8088" || c.PublicURL == "http://"+c.ListenAddr {
		c.PublicURL = "https://manager.localhost:" + port
	}
	if c.ProxyPublicURLTemplate == "" || c.ProxyPublicURLTemplate == "http://127.0.0.1:{port}" {
		c.ProxyPublicURLTemplate = "https://{id}.localhost:" + port
	}
	if err := validateLocalOrigin(c.PublicURL); err != nil {
		return err
	}
	return validateLocalOrigin(strings.ReplaceAll(c.ProxyPublicURLTemplate, "{id}", "primary"))
}

func validateLocalOrigin(origin string) error {
	u, err := url.Parse(origin)
	if err != nil || u.Scheme != "https" || !localtls.CoversHost(u.Hostname()) {
		return fmt.Errorf("local_tls requires HTTPS origins covered by localhost, *.localhost, 127.0.0.1 or ::1: %q", origin)
	}
	return nil
}

func (c Config) configureLocalInstance(id string, instance *GatewayInstance) error {
	if !instance.UseGlobalDefaults {
		// Legacy default HTTP endpoints can move to the local shared listener
		// without changing installation paths or network inheritance settings.
		u, _ := url.Parse(instance.ProxyPublicURL)
		if instance.ProxyPublicURL == "" || (u != nil && u.Scheme == "http" && localtls.CoversHost(u.Hostname())) {
			instance.ProxyPublicURL = strings.ReplaceAll(c.ProxyPublicURLTemplate, "{id}", id)
		}
	}
	if instance.ProxyToken == "" {
		var secret [32]byte
		if _, err := rand.Read(secret[:]); err != nil {
			return err
		}
		instance.ProxyToken = hex.EncodeToString(secret[:])
	}
	return nil
}
