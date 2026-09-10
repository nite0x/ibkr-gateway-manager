package service

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"net/http/httputil"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/nite0x/ibkr-gateway-manager/gateway"
	"github.com/nite0x/ibkr-gateway-manager/internal/appconfig"
)

const (
	browserSessionCookie = "ibkr_gateway_manager_session"
	upstreamCookieBase   = "ibkr_gateway_upstream_"
	dedicatedLoginPath   = "/_manager/login"
)

type Gateway interface {
	Status() gateway.GatewayStatus
	StartGateway(context.Context) error
	StopGateway(bool) error
	Reconnect() error
	Upgrade(context.Context) error
	Rollback(context.Context) error
	Reconfigure(gateway.Config) error
	Shutdown() error
	BaseURL() string
}

// SessionController is optional for older embedders of the process-only interface.
type SessionController interface {
	RecoverSession(context.Context, bool) error
	ResumeSession(context.Context) error
	Logout(context.Context) error
}

type GatewayFactory func(gateway.Config) Gateway

type Server struct {
	configPath string
	config     appconfig.Config
	factory    GatewayFactory
	now        func() time.Time

	mu            sync.Mutex
	tickets       map[string]loginTicket
	sessions      map[string]browserSession
	loginAttempts map[string]loginAttemptWindow
	opMu          sync.Mutex
	closing       bool // protected by opMu

	registryMu       sync.RWMutex
	managers         map[string]Gateway
	dedicatedProxies map[string]*httputil.ReverseProxy

	proxyMu               sync.Mutex
	proxyListeners        map[string]*gatewayProxyListener
	sharedProxyListener   *sharedProxyListener
	proxyListenersStarted bool
}

// New preserves the single-Gateway constructor for existing embedders.
func New(manager Gateway, configPath string, cfg appconfig.Config) (*Server, error) {
	if manager == nil {
		return nil, errors.New("gateway manager is required")
	}
	if len(cfg.Gateways) == 0 {
		cfg.Gateways = map[string]appconfig.GatewayInstance{
			appconfig.DefaultGatewayID: {Config: gateway.Config{GatewayURL: manager.BaseURL()}},
		}
	}
	id := defaultGatewayID(cfg.Gateways)
	if id == "" {
		return nil, errors.New("single-Gateway constructor requires a default or sole gateway")
	}
	return newServer(map[string]Gateway{id: manager}, nil, configPath, cfg)
}

// NewRegistry creates one independent manager and proxy per configured ID.
func NewRegistry(configPath string, cfg appconfig.Config, factory GatewayFactory) (*Server, error) {
	if factory == nil {
		return nil, errors.New("gateway factory is required")
	}
	if err := cfg.Validate(filepath.Dir(configPath)); err != nil {
		return nil, err
	}
	managers := make(map[string]Gateway, len(cfg.Gateways))
	for id, instance := range cfg.Gateways {
		manager := factory(instance.Config)
		if manager == nil {
			return nil, fmt.Errorf("gateway factory returned nil for %q", id)
		}
		managers[id] = manager
	}
	return newServer(managers, factory, configPath, cfg)
}

func newServer(managers map[string]Gateway, factory GatewayFactory, configPath string, cfg appconfig.Config) (*Server, error) {
	if err := cfg.ValidateAuth(); err != nil {
		return nil, err
	}
	dedicatedProxies := make(map[string]*httputil.ReverseProxy, len(managers))
	for id, manager := range managers {
		if instance := cfg.Gateways[id]; instance.ProxyPublicURL != "" {
			proxy, err := newGatewayProxy(manager.BaseURL(), instance.ProxyPublicURL, loginCompletionNotifier(manager))
			if err != nil {
				return nil, fmt.Errorf("gateway %q dedicated proxy: %w", id, err)
			}
			dedicatedProxies[id] = proxy
		}
	}
	return &Server{
		configPath: configPath, config: cfg, factory: factory, now: time.Now,
		tickets: map[string]loginTicket{}, sessions: map[string]browserSession{},
		managers: managers, dedicatedProxies: dedicatedProxies,
		proxyListeners: map[string]*gatewayProxyListener{},
	}, nil
}

// StartConfigured starts each instance whose own auto_start setting is true.
func (s *Server) StartConfigured(ctx context.Context) {
	s.registryMu.RLock()
	managers := cloneManagers(s.managers)
	s.registryMu.RUnlock()
	instances := s.currentConfig().Gateways
	for _, id := range sortedGatewayIDs(instances) {
		manager := managers[id]
		if !instances[id].AutoStart || manager == nil {
			continue
		}
		go func(id string, manager Gateway) {
			s.opMu.Lock()
			defer s.opMu.Unlock()
			if s.closing || !s.currentConfig().Gateways[id].AutoStart {
				return
			}
			var exists bool
			manager, exists = s.gateway(id)
			if !exists {
				return
			}
			start := manager.StartGateway
			if auto, ok := manager.(interface{ AutoStartGateway(context.Context) error }); ok {
				start = auto.AutoStartGateway
			}
			if err := start(ctx); err != nil {
				log.Printf("gateway %s auto-start failed: %v", id, err)
			}
		}(id, manager)
	}
}

// Shutdown applies every instance's configured lifecycle independently.
func (s *Server) Shutdown() error {
	s.opMu.Lock()
	defer s.opMu.Unlock()
	s.closing = true
	proxyCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	proxyErr := s.ShutdownProxyListeners(proxyCtx)
	cancel()
	s.registryMu.RLock()
	managers := cloneManagers(s.managers)
	s.registryMu.RUnlock()
	var result []error
	if proxyErr != nil {
		result = append(result, proxyErr)
	}
	for _, id := range sortedManagerIDs(managers) {
		if err := managers[id].Shutdown(); err != nil {
			result = append(result, fmt.Errorf("gateway %s: %w", id, err))
		}
	}
	return errors.Join(result...)
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch {
	case r.URL.Path == "/healthz" && r.Method == http.MethodGet:
		writeJSON(w, http.StatusOK, map[string]any{"status": "ok"})
	case r.URL.Path == "/" && r.Method == http.MethodGet:
		http.Redirect(w, r, "/manager/", http.StatusFound)
	case strings.HasPrefix(r.URL.Path, "/auth/v1/"):
		s.serveAuth(w, r)
	case isManagerUIPath(r.URL.Path):
		s.serveManagerUI(w, r)
	case strings.HasPrefix(r.URL.Path, "/management/v1/"):
		s.serveManagement(w, r)
	default:
		writeJSON(w, http.StatusNotFound, map[string]any{"error": "not found"})
	}
}

func (s *Server) serveManagement(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if r.Method != http.MethodGet {
		s.opMu.Lock()
		defer s.opMu.Unlock()
		if s.closing {
			writeJSON(w, http.StatusServiceUnavailable, map[string]any{"error": "manager is shutting down"})
			return
		}
	}
	if !s.authorizedManagement(r) {
		w.Header().Set("WWW-Authenticate", "Bearer")
		writeJSON(w, http.StatusUnauthorized, map[string]any{"error": "unauthorized"})
		return
	}
	if r.URL.Path == "/management/v1/gateways" && r.Method == http.MethodGet {
		writeJSON(w, http.StatusOK, map[string]any{"gateways": s.gatewayStatuses()})
		return
	}
	if id, action, ok := parseGatewayManagementPath(r.URL.Path); ok {
		s.serveGatewayOperation(w, r, id, action)
		return
	}
	switch {
	case r.URL.Path == "/management/v1/local-tls" && r.Method == http.MethodGet:
		s.serveLocalTLS(w, r)
	case r.URL.Path == "/management/v1/local-tls/ca.crt" && r.Method == http.MethodGet:
		s.serveLocalTLS(w, r)
	case r.URL.Path == "/management/v1/config" && r.Method == http.MethodGet:
		cfg := s.currentConfig()
		cfg.APIToken = ""
		cfg.Password = ""
		gateways := make(map[string]appconfig.GatewayInstance, len(cfg.Gateways))
		for id, instance := range cfg.Gateways {
			instance.ProxyToken = ""
			gateways[id] = instance
		}
		cfg.Gateways = gateways
		writeJSON(w, http.StatusOK, cfg)
	case r.URL.Path == "/management/v1/config" && r.Method == http.MethodPut:
		s.updateConfig(w, r)
	default:
		writeJSON(w, http.StatusNotFound, map[string]any{"error": "not found"})
	}
}

func (s *Server) serveGatewayOperation(w http.ResponseWriter, r *http.Request, id, action string) {
	manager, ok := s.gateway(id)
	if !ok {
		writeJSON(w, http.StatusNotFound, map[string]any{"error": "gateway not found"})
		return
	}
	switch {
	case action == "status" && r.Method == http.MethodGet:
		writeJSON(w, http.StatusOK, s.gatewayStatus(id, manager))
	case action == "login-ticket" && r.Method == http.MethodPost:
		s.issueLoginTicket(w, r, id)
	case action == "start" && r.Method == http.MethodPost:
		s.runOperation(w, func() error { return manager.StartGateway(context.WithoutCancel(r.Context())) }, "started")
	case action == "stop" && r.Method == http.MethodPost:
		keep := r.URL.Query().Get("keep_session") == "true"
		s.runOperation(w, func() error { return manager.StopGateway(keep) }, "stopped")
	case (action == "reconnect" || action == "restart") && r.Method == http.MethodPost:
		s.runOperation(w, manager.Reconnect, "reconnected")
	case (action == "recover" || action == "takeover" || action == "logout" || action == "resume") && r.Method == http.MethodPost:
		controller, supported := manager.(SessionController)
		if !supported {
			writeJSON(w, http.StatusNotImplemented, map[string]any{"error": "session control is unavailable"})
			return
		}
		s.runOperation(w, func() error {
			switch action {
			case "resume":
				return controller.ResumeSession(r.Context())
			case "logout":
				err := controller.Logout(r.Context())
				// Revoke this instance's manager browser sessions even when IBKR
				// cannot confirm logout; another instance remains untouched.
				s.mu.Lock()
				for token, session := range s.sessions {
					if session.GatewayID == id {
						delete(s.sessions, token)
					}
				}
				for token, ticket := range s.tickets {
					if ticket.GatewayID == id {
						delete(s.tickets, token)
					}
				}
				s.mu.Unlock()
				return err
			default:
				return controller.RecoverSession(r.Context(), action == "takeover")
			}
		}, action)
	case action == "upgrade" && r.Method == http.MethodPost:
		s.runOperation(w, func() error { return manager.Upgrade(context.WithoutCancel(r.Context())) }, "upgraded")
	case action == "rollback" && r.Method == http.MethodPost:
		s.runOperation(w, func() error { return manager.Rollback(context.WithoutCancel(r.Context())) }, "rolled_back")
	default:
		writeJSON(w, http.StatusNotFound, map[string]any{"error": "not found"})
	}
}

func (s *Server) runOperation(w http.ResponseWriter, operation func() error, status string) {
	if err := operation(); err != nil {
		writeJSON(w, http.StatusBadGateway, map[string]any{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"status": status})
}

func (s *Server) gateway(id string) (Gateway, bool) {
	s.registryMu.RLock()
	manager, ok := s.managers[id]
	s.registryMu.RUnlock()
	return manager, ok
}

func defaultGatewayID(instances map[string]appconfig.GatewayInstance) string {
	if _, ok := instances[appconfig.DefaultGatewayID]; ok {
		return appconfig.DefaultGatewayID
	}
	// Configurations written by the first multi-Gateway preview used `default`.
	if _, ok := instances["default"]; ok {
		return "default"
	}
	if len(instances) == 1 {
		for id := range instances {
			return id
		}
	}
	return ""
}

type gatewayStatus struct {
	ID                   string                `json:"id"`
	AutoStart            bool                  `json:"auto_start"`
	ProxyListenAddr      string                `json:"proxy_listen_addr,omitempty"`
	ProxyURL             string                `json:"proxy_url,omitempty"`
	ProxyListening       bool                  `json:"proxy_listening"`
	ProxyTokenConfigured bool                  `json:"proxy_token_configured"`
	Status               gateway.GatewayStatus `json:"status"`
}

func (s *Server) gatewayStatuses() []gatewayStatus {
	cfg := s.currentConfig()
	result := make([]gatewayStatus, 0, len(cfg.Gateways))
	for _, id := range sortedGatewayIDs(cfg.Gateways) {
		manager, ok := s.gateway(id)
		if ok {
			instance := cfg.Gateways[id]
			result = append(result, gatewayStatus{
				ID: id, AutoStart: instance.AutoStart,
				ProxyListenAddr: instance.ProxyListenAddr, ProxyURL: instance.ProxyPublicURL,
				ProxyListening: s.proxyIsListening(id), ProxyTokenConfigured: instance.ProxyToken != "",
				Status: s.gatewayStatus(id, manager),
			})
		}
	}
	return result
}

func (s *Server) gatewayStatus(id string, manager Gateway) gateway.GatewayStatus {
	status := manager.Status()
	instance, ok := s.currentConfig().Gateways[id]
	if !ok || instance.ProxyPublicURL == "" {
		status.LoginURL = ""
		return status
	}
	status.LoginURL = strings.TrimRight(instance.ProxyPublicURL, "/") + "/sso/Login"
	return status
}

func parseGatewayManagementPath(path string) (id, action string, ok bool) {
	const prefix = "/management/v1/gateways/"
	if !strings.HasPrefix(path, prefix) {
		return "", "", false
	}
	parts := strings.Split(strings.TrimPrefix(path, prefix), "/")
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return "", "", false
	}
	return parts[0], parts[1], true
}

func sortedGatewayIDs(instances map[string]appconfig.GatewayInstance) []string {
	ids := make([]string, 0, len(instances))
	for id := range instances {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	return ids
}

func sortedManagerIDs(managers map[string]Gateway) []string {
	ids := make([]string, 0, len(managers))
	for id := range managers {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	return ids
}

func cloneManagers(source map[string]Gateway) map[string]Gateway {
	result := make(map[string]Gateway, len(source))
	for id, manager := range source {
		result[id] = manager
	}
	return result
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}
