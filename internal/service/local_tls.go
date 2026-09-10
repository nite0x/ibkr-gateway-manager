package service

import (
	"net/http"
	"net/url"
	"path/filepath"
	"strings"

	"github.com/nite0x/ibkr-gateway-manager/internal/appconfig"
	"github.com/nite0x/ibkr-gateway-manager/internal/localtls"
)

func localTLSHosts(cfg appconfig.Config) []string {
	manager, _ := url.Parse(cfg.PublicURL)
	hosts := []string{manager.Hostname()}
	for _, instance := range cfg.Gateways {
		u, _ := url.Parse(instance.ProxyPublicURL)
		hosts = append(hosts, u.Hostname())
	}
	return hosts
}

// Invoked only after the management authentication check. The private identity
// is never served; CA export is reconstructed from a parsed X.509 certificate.
func (s *Server) serveLocalTLS(w http.ResponseWriter, r *http.Request) {
	if !s.currentConfig().LocalTLS {
		writeJSON(w, http.StatusNotFound, map[string]any{"error": "local TLS is not enabled"})
		return
	}
	status, ca, err := localtls.Inspect(filepath.Join(filepath.Dir(s.configPath), "tls"))
	if err != nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{"error": "local certificate metadata unavailable; check manager logs and local-tls-status"})
		return
	}
	if strings.HasSuffix(r.URL.Path, "/ca.crt") {
		w.Header().Set("Content-Type", "application/x-pem-file")
		w.Header().Set("Content-Disposition", `attachment; filename="ibkr-local-ca.crt"`)
		w.Header().Set("X-Content-Type-Options", "nosniff")
		_, _ = w.Write(ca)
		return
	}
	writeJSON(w, http.StatusOK, status)
}
