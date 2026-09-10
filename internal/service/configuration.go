package service

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httputil"
	"path/filepath"
	"reflect"

	"github.com/nite0x/ibkr-gateway-manager/gateway"
	"github.com/nite0x/ibkr-gateway-manager/internal/appconfig"
)

func (s *Server) updateConfig(w http.ResponseWriter, r *http.Request) {
	var incoming struct {
		appconfig.Config
		Port                   *int      `json:"port"`
		PublicDomain           *string   `json:"public_domain"`
		APIToken               *string   `json:"api_token"`
		ListenAddr             *string   `json:"listen_addr"`
		PublicURL              *string   `json:"public_url"`
		SharedGatewayDir       *string   `json:"shared_gateway_dir"`
		GatewayRootDir         *string   `json:"gateway_root_dir"`
		BundledGatewayDir      *string   `json:"bundled_gateway_dir"`
		DownloadProxy          *string   `json:"download_proxy"`
		GatewayProxyHost       *string   `json:"gateway_proxy_host"`
		GatewayAllowIPs        *[]string `json:"gateway_allow_ips"`
		ProxyListenHost        *string   `json:"proxy_listen_host"`
		ProxyPublicURLTemplate *string   `json:"proxy_public_url_template"`
		SharedProxyListenAddr  *string   `json:"shared_proxy_listen_addr"`
		ProxyTLSTerminated     *bool     `json:"proxy_tls_terminated"`
		LocalTLS               *bool     `json:"local_tls"`
		ProxyTLSCertFile       *string   `json:"proxy_tls_cert_file"`
		ProxyTLSKeyFile        *string   `json:"proxy_tls_key_file"`
	}
	decoder := json.NewDecoder(io.LimitReader(r.Body, 1<<20))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&incoming); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid config", "details": err.Error()})
		return
	}
	updated := s.currentConfig()
	if (incoming.Port != nil && *incoming.Port != updated.Port) ||
		(incoming.PublicDomain != nil && *incoming.PublicDomain != updated.PublicDomain) {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "port and public_domain can only be changed in startup configuration"})
		return
	}
	if incoming.LocalTLS != nil && *incoming.LocalTLS != updated.LocalTLS {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "local_tls can only be changed in startup configuration"})
		return
	}
	if incoming.APIToken != nil {
		if *incoming.APIToken != "" && *incoming.APIToken != updated.APIToken {
			writeJSON(w, http.StatusBadRequest, map[string]any{"error": "generate API tokens through /auth/v1/api-token"})
			return
		}
	}
	if (incoming.Username != "" && incoming.Username != updated.Username) ||
		(incoming.Password != "" && incoming.Password != updated.Password) ||
		(incoming.SessionTTLMinutes != 0 && incoming.SessionTTLMinutes != updated.SessionTTLMinutes) {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "username, password and session_ttl_minutes can only be changed in startup configuration"})
		return
	}
	if incoming.ListenAddr != nil {
		updated.ListenAddr = *incoming.ListenAddr
	}
	if incoming.PublicURL != nil {
		updated.PublicURL = *incoming.PublicURL
	}
	if incoming.SharedGatewayDir != nil {
		updated.SharedGatewayDir = *incoming.SharedGatewayDir
	}
	if incoming.GatewayRootDir != nil {
		updated.GatewayRootDir = *incoming.GatewayRootDir
	}
	if incoming.BundledGatewayDir != nil {
		updated.BundledGatewayDir = *incoming.BundledGatewayDir
	}
	if incoming.DownloadProxy != nil {
		updated.DownloadProxy = *incoming.DownloadProxy
	}
	if incoming.GatewayProxyHost != nil {
		updated.GatewayProxyHost = *incoming.GatewayProxyHost
	}
	if incoming.GatewayAllowIPs != nil {
		updated.GatewayAllowIPs = *incoming.GatewayAllowIPs
	}
	if incoming.ProxyListenHost != nil {
		updated.ProxyListenHost = *incoming.ProxyListenHost
	}
	if incoming.ProxyPublicURLTemplate != nil {
		updated.ProxyPublicURLTemplate = *incoming.ProxyPublicURLTemplate
	}
	if incoming.SharedProxyListenAddr != nil {
		updated.SharedProxyListenAddr = *incoming.SharedProxyListenAddr
	}
	if incoming.ProxyTLSTerminated != nil {
		updated.ProxyTLSTerminated = *incoming.ProxyTLSTerminated
	}
	if incoming.ProxyTLSCertFile != nil {
		updated.ProxyTLSCertFile = *incoming.ProxyTLSCertFile
	}
	if incoming.ProxyTLSKeyFile != nil {
		updated.ProxyTLSKeyFile = *incoming.ProxyTLSKeyFile
	}
	switch {
	case incoming.Gateways != nil:
		for id, instance := range incoming.Gateways {
			previous := updated.Gateways[id]
			if instance.UseGlobalDefaults && previous.UseGlobalDefaults && instance.GatewayConfigFile == "" {
				instance.GatewayDir = previous.GatewayDir
				instance.GatewayConfigFile = previous.GatewayConfigFile
				instance.GatewayStateDir = previous.GatewayStateDir
			}
			if instance.ProxyToken == "" {
				instance.ProxyToken = updated.Gateways[id].ProxyToken
				if instance.ProxyToken == "" {
					var token [32]byte
					if _, err := rand.Read(token[:]); err != nil {
						writeJSON(w, http.StatusInternalServerError, map[string]any{"error": "could not generate instance token"})
						return
					}
					instance.ProxyToken = hex.EncodeToString(token[:])
				}
			}
			incoming.Gateways[id] = instance
		}
		updated.Gateways, updated.Gateway, updated.AutoStart = incoming.Gateways, nil, nil
	case incoming.Gateway != nil:
		updated.Gateways, updated.Gateway, updated.AutoStart = nil, incoming.Gateway, incoming.AutoStart
	default:
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "gateways must be an object; use {} to remove all instances"})
		return
	}
	if err := updated.Validate(filepath.Dir(s.configPath)); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": err.Error()})
		return
	}
	if err := s.applyConfig(context.WithoutCancel(r.Context()), updated); err != nil {
		writeJSON(w, http.StatusBadGateway, map[string]any{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"status": "reconfigured"})
}

// applyConfig requires opMu. Prepare fallible resources before changing processes;
// undo every attempted mutation in reverse order if execution or publication fails.
func (s *Server) applyConfig(ctx context.Context, updated appconfig.Config) (resultErr error) {
	oldConfig := s.currentConfig()
	if updated.LocalTLS != oldConfig.LocalTLS {
		return errors.New("changing local_tls requires restarting the manager")
	}
	if updated.ListenAddr != oldConfig.ListenAddr {
		return errors.New("listen_addr cannot be changed while running; edit the configuration file and restart the manager")
	}
	if (updated.SharedProxyListenAddr == "") != (oldConfig.SharedProxyListenAddr == "") {
		return errors.New("enabling or disabling the shared proxy requires editing the configuration file and restarting the manager")
	}
	pending, err := appconfig.PrepareSave(s.configPath, updated)
	if err != nil {
		return fmt.Errorf("prepare config: %w", err)
	}
	defer pending.Abort()
	reconcile, err := s.prepareProxyListenerReconcile(updated)
	if err != nil {
		return err
	}
	var undo []func() error
	defer func() {
		if resultErr == nil {
			return
		}
		reconcile.rollback()
		for i := len(undo) - 1; i >= 0; i-- {
			if err := undo[i](); err != nil {
				resultErr = errors.Join(resultErr, fmt.Errorf("configuration rollback: %w", err))
			}
		}
	}()
	s.registryMu.RLock()
	oldManagers := cloneManagers(s.managers)
	s.registryMu.RUnlock()
	newManagers := make(map[string]Gateway, len(updated.Gateways))
	newProxies := make(map[string]*httputil.ReverseProxy, len(updated.Gateways))
	// Prepare managers and proxies without starting or reconfiguring them.
	for _, id := range sortedGatewayIDs(updated.Gateways) {
		instance := updated.Gateways[id]
		manager, exists := oldManagers[id]
		if !exists {
			if s.factory == nil {
				return errors.New("this server cannot add gateways at runtime")
			}
			manager = s.factory(instance.Config)
			if manager == nil {
				return fmt.Errorf("gateway factory returned nil for %q", id)
			}
		}
		newManagers[id] = manager
		if instance.ProxyPublicURL != "" {
			target := instance.GatewayURL
			if exists && reflect.DeepEqual(oldConfig.Gateways[id].Config, instance.Config) {
				target = manager.BaseURL()
			}
			proxy, err := newGatewayProxy(target, instance.ProxyPublicURL, loginCompletionNotifier(manager))
			if err != nil {
				return fmt.Errorf("gateway %q dedicated proxy: %w", id, err)
			}
			newProxies[id] = proxy
		}
	}
	for _, id := range sortedGatewayIDs(updated.Gateways) {
		instance, manager := updated.Gateways[id], newManagers[id]
		oldInstance, exists := oldConfig.Gateways[id]
		if !exists {
			if instance.AutoStart {
				undo = append(undo, func() error { return manager.StopGateway(false) })
				if err := manager.StartGateway(ctx); err != nil {
					return fmt.Errorf("start gateway %q: %w", id, err)
				}
			}
			continue
		}
		changed := !reflect.DeepEqual(oldInstance.Config, instance.Config)
		if !changed && (oldInstance.AutoStart || !instance.AutoStart) {
			continue
		}
		previous := manager.Status()
		undo = append(undo, func() error { return restoreGatewayConfiguration(manager, oldInstance.Config, previous, changed) })
		if changed {
			if err := manager.Reconfigure(instance.Config); err != nil {
				return fmt.Errorf("reconfigure gateway %q: %w", id, err)
			}
		} else if err := manager.StartGateway(ctx); err != nil {
			return fmt.Errorf("start gateway %q: %w", id, err)
		}
	}
	for _, id := range sortedManagerIDs(oldManagers) {
		if _, retained := newManagers[id]; retained {
			continue
		}
		manager, instance := oldManagers[id], oldConfig.Gateways[id]
		previous := manager.Status()
		undo = append(undo, func() error { return restoreGatewayConfiguration(manager, instance.Config, previous, false) })
		if err := manager.StopGateway(false); err != nil {
			return fmt.Errorf("remove gateway %q: %w", id, err)
		}
	}
	if err := pending.Commit(); err != nil {
		return fmt.Errorf("save config: %w", err)
	}
	s.registryMu.Lock()
	s.managers, s.dedicatedProxies = newManagers, newProxies
	s.registryMu.Unlock()
	s.mu.Lock()
	s.config = updated.Clone()
	// Credentials and tickets must not survive removal or credential rotation.
	for token, session := range s.sessions {
		if session.GatewayID == "" {
			continue
		}
		old, exists := oldConfig.Gateways[session.GatewayID]
		next, retained := updated.Gateways[session.GatewayID]
		if !exists || !retained || old.ProxyToken != next.ProxyToken {
			delete(s.sessions, token)
		}
	}
	for token, ticket := range s.tickets {
		old, exists := oldConfig.Gateways[ticket.GatewayID]
		next, retained := updated.Gateways[ticket.GatewayID]
		if !exists || !retained || old.ProxyToken != next.ProxyToken {
			delete(s.tickets, token)
		}
	}
	s.mu.Unlock()
	reconcile.commit(s)
	return nil
}

// Modern managers restore saved intent as well as process state. Legacy embedders
// retain their process-only interface and receive a best-effort compensation.
func restoreGatewayConfiguration(manager Gateway, cfg gateway.Config, previous gateway.GatewayStatus, changed bool) error {
	if restorer, ok := manager.(interface {
		RestoreConfiguration(gateway.Config, gateway.GatewayStatus) error
	}); ok {
		return restorer.RestoreConfiguration(cfg, previous)
	}
	if changed {
		if err := manager.Reconfigure(cfg); err != nil {
			return err
		}
	}
	if previous.Running {
		return manager.StartGateway(context.Background())
	}
	return manager.StopGateway(previous.State == "detached")
}

func (s *Server) currentConfig() appconfig.Config {
	s.mu.Lock()
	cfg := s.config.Clone()
	s.mu.Unlock()
	return cfg
}
