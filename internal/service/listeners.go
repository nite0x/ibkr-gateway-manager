package service

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/url"
	"path/filepath"
	"strings"
	"time"

	"github.com/nite0x/ibkr-gateway-manager/internal/appconfig"
	"github.com/nite0x/ibkr-gateway-manager/internal/localtls"
)

type gatewayProxyListener struct {
	id         string
	listenAddr string
	publicURL  string
	server     *http.Server
	listener   net.Listener
}

type sharedProxyListener struct {
	listenAddr        string
	certFile          string
	keyFile           string
	tlsTerminated     bool
	localTLS          bool
	localCertificates *localtls.Manager
	server            *http.Server
	listener          net.Listener
}

type proxyListenerReconcile struct {
	next          map[string]*gatewayProxyListener
	started       []*gatewayProxyListener
	retired       []*gatewayProxyListener
	sharedNext    *sharedProxyListener
	sharedStarted *sharedProxyListener
	sharedRetired *sharedProxyListener
}

// StartProxyListeners opens each instance's compatibility listener and the
// optional shared HTTPS listener that dispatches browser traffic by hostname.
func (s *Server) StartProxyListeners() error {
	s.proxyMu.Lock()
	defer s.proxyMu.Unlock()
	if s.proxyListenersStarted {
		return nil
	}
	cfg := s.currentConfig()
	started := make(map[string]*gatewayProxyListener)
	if cfg.SharedProxyListenAddr == "" {
		for _, id := range sortedGatewayIDs(cfg.Gateways) {
			instance := cfg.Gateways[id]
			if instance.ProxyListenAddr == "" {
				continue
			}
			listener, err := s.startProxyListener(id, instance, cfg)
			if err != nil {
				for _, running := range started {
					closeProxyListener(running)
				}
				return fmt.Errorf("start gateway %q proxy: %w", id, err)
			}
			started[id] = listener
		}
	}
	shared, err := s.startSharedProxyListener(cfg)
	if err != nil {
		for _, running := range started {
			closeProxyListener(running)
		}
		return fmt.Errorf("start shared proxy: %w", err)
	}
	s.proxyListeners = started
	s.sharedProxyListener = shared
	s.proxyListenersStarted = true
	return nil
}

func (s *Server) startSharedProxyListener(cfg appconfig.Config) (*sharedProxyListener, error) {
	if cfg.SharedProxyListenAddr == "" {
		return nil, nil
	}
	listener, err := net.Listen("tcp", cfg.SharedProxyListenAddr)
	if err != nil {
		return nil, err
	}
	var localCertificates *localtls.Manager
	if !cfg.ProxyTLSTerminated {
		tlsConfig := &tls.Config{MinVersion: tls.VersionTLS12}
		if cfg.LocalTLS {
			certificates, err := localtls.Open(filepath.Join(filepath.Dir(s.configPath), "tls"), localTLSHosts(cfg)...)
			if err != nil {
				_ = listener.Close()
				return nil, fmt.Errorf("initialize local TLS: %w", err)
			}
			tlsConfig.GetCertificate = certificates.GetCertificate
			localCertificates = certificates
			log.Printf("Local HTTPS enabled; export the public CA with -export-local-ca and trust it on the host once")
		} else {
			certificate, err := tls.LoadX509KeyPair(cfg.ProxyTLSCertFile, cfg.ProxyTLSKeyFile)
			if err != nil {
				_ = listener.Close()
				return nil, fmt.Errorf("load proxy TLS certificate: %w", err)
			}
			tlsConfig.Certificates = []tls.Certificate{certificate}
		}
		listener = tls.NewListener(listener, tlsConfig)
	}
	server := &http.Server{
		Handler: http.HandlerFunc(s.ServeSharedGatewayProxy), ReadHeaderTimeout: 10 * time.Second, IdleTimeout: 90 * time.Second,
	}
	result := &sharedProxyListener{
		listenAddr: cfg.SharedProxyListenAddr, certFile: cfg.ProxyTLSCertFile, keyFile: cfg.ProxyTLSKeyFile,
		tlsTerminated: cfg.ProxyTLSTerminated, localTLS: cfg.LocalTLS,
		localCertificates: localCertificates,
		server:            server, listener: listener,
	}
	go func() {
		transport := "HTTPS"
		if cfg.ProxyTLSTerminated {
			transport = "HTTP behind TLS-terminating proxy"
		}
		log.Printf("IBKR shared %s proxy listening at %s", transport, cfg.SharedProxyListenAddr)
		if err := server.Serve(listener); err != nil && !errors.Is(err, http.ErrServerClosed) && !errors.Is(err, net.ErrClosed) {
			log.Printf("shared HTTPS proxy stopped unexpectedly: %v", err)
		}
	}()
	return result, nil
}

// ServeSharedGatewayProxy routes the manager and Gateway origins by hostname.
func (s *Server) ServeSharedGatewayProxy(w http.ResponseWriter, r *http.Request) {
	// Platform health checks do not necessarily use the configured manager Host.
	// Keep this endpoint host-independent while all other shared traffic remains
	// restricted to explicitly configured public origins.
	if r.Method == http.MethodGet && r.URL.Path == "/healthz" {
		s.ServeHTTP(w, r)
		return
	}
	host := requestHostname(r.Host)
	cfg := s.currentConfig()
	managerURL, err := url.Parse(cfg.PublicURL)
	if err == nil && strings.EqualFold(strings.TrimSuffix(managerURL.Hostname(), "."), host) {
		s.ServeHTTP(w, r)
		return
	}
	for _, id := range sortedGatewayIDs(cfg.Gateways) {
		publicURL, err := url.Parse(cfg.Gateways[id].ProxyPublicURL)
		if err == nil && strings.EqualFold(strings.TrimSuffix(publicURL.Hostname(), "."), host) {
			s.ServeGatewayProxy(id, w, r)
			return
		}
	}
	writeJSON(w, http.StatusMisdirectedRequest, map[string]any{"error": "unknown shared HTTPS hostname"})
}

func requestHostname(hostport string) string {
	host := strings.TrimSpace(hostport)
	if parsed, _, err := net.SplitHostPort(host); err == nil {
		host = parsed
	}
	return strings.ToLower(strings.TrimSuffix(strings.Trim(host, "[]"), "."))
}

func (s *Server) startProxyListener(id string, instance appconfig.GatewayInstance, cfg appconfig.Config) (*gatewayProxyListener, error) {
	listener, err := net.Listen("tcp", instance.ProxyListenAddr)
	if err != nil {
		return nil, err
	}
	publicURL, err := url.Parse(instance.ProxyPublicURL)
	if err != nil {
		_ = listener.Close()
		return nil, err
	}
	if publicURL.Scheme == "https" {
		certificate, err := tls.LoadX509KeyPair(cfg.ProxyTLSCertFile, cfg.ProxyTLSKeyFile)
		if err != nil {
			_ = listener.Close()
			return nil, fmt.Errorf("load proxy TLS certificate: %w", err)
		}
		listener = tls.NewListener(listener, &tls.Config{
			MinVersion:   tls.VersionTLS12,
			Certificates: []tls.Certificate{certificate},
		})
	}
	server := &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			s.ServeGatewayProxy(id, w, r)
		}),
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       90 * time.Second,
	}
	result := &gatewayProxyListener{
		id: id, listenAddr: instance.ProxyListenAddr, publicURL: instance.ProxyPublicURL,
		server: server, listener: listener,
	}
	go func() {
		log.Printf("IBKR Gateway %s compatibility proxy listening on %s (public origin %s)", id, instance.ProxyListenAddr, instance.ProxyPublicURL)
		if err := server.Serve(listener); err != nil && !errors.Is(err, http.ErrServerClosed) && !errors.Is(err, net.ErrClosed) {
			log.Printf("gateway %s proxy stopped unexpectedly: %v", id, err)
		}
	}()
	return result, nil
}

// ShutdownProxyListeners gracefully closes every dedicated listener.
func (s *Server) ShutdownProxyListeners(ctx context.Context) error {
	s.proxyMu.Lock()
	listeners := s.proxyListeners
	shared := s.sharedProxyListener
	s.proxyListeners = map[string]*gatewayProxyListener{}
	s.sharedProxyListener = nil
	s.proxyListenersStarted = false
	s.proxyMu.Unlock()
	var result []error
	for id, listener := range listeners {
		if err := listener.server.Shutdown(ctx); err != nil {
			result = append(result, fmt.Errorf("gateway %s proxy: %w", id, err))
		}
	}
	if shared != nil {
		if err := shared.server.Shutdown(ctx); err != nil {
			result = append(result, fmt.Errorf("shared proxy: %w", err))
		}
	}
	return errors.Join(result...)
}

func closeProxyListener(listener *gatewayProxyListener) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = listener.server.Shutdown(ctx)
	_ = listener.listener.Close()
}

func closeSharedProxyListener(listener *sharedProxyListener) {
	if listener == nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = listener.server.Shutdown(ctx)
	_ = listener.listener.Close()
}

func (s *Server) prepareProxyListenerReconcile(updated appconfig.Config) (*proxyListenerReconcile, error) {
	s.proxyMu.Lock()
	listenersStarted := s.proxyListenersStarted
	current := make(map[string]*gatewayProxyListener, len(s.proxyListeners))
	for id, listener := range s.proxyListeners {
		current[id] = listener
	}
	currentShared := s.sharedProxyListener
	s.proxyMu.Unlock()
	result := &proxyListenerReconcile{next: map[string]*gatewayProxyListener{}}
	if !listenersStarted {
		return result, nil
	}
	if updated.SharedProxyListenAddr == "" {
		for _, id := range sortedGatewayIDs(updated.Gateways) {
			instance := updated.Gateways[id]
			if instance.ProxyListenAddr == "" {
				continue
			}
			if existing, ok := current[id]; ok && existing.listenAddr == instance.ProxyListenAddr {
				oldScheme := proxyURLScheme(existing.publicURL)
				newScheme := proxyURLScheme(instance.ProxyPublicURL)
				if oldScheme != newScheme {
					result.rollback()
					return nil, fmt.Errorf("gateway %q proxy HTTP/HTTPS mode changed on the same address; restart the manager to apply it", id)
				}
				result.next[id] = existing
				continue
			}
			for oldID, existing := range current {
				if oldID != id && existing.listenAddr == instance.ProxyListenAddr {
					result.rollback()
					return nil, fmt.Errorf("proxy address %s is currently owned by gateway %q; restart the manager to reassign it", instance.ProxyListenAddr, oldID)
				}
			}
			listener, err := s.startProxyListener(id, instance, updated)
			if err != nil {
				result.rollback()
				return nil, fmt.Errorf("start gateway %q proxy: %w", id, err)
			}
			result.next[id] = listener
			result.started = append(result.started, listener)
		}
	}
	for id, existing := range current {
		if next, retained := result.next[id]; !retained || next != existing {
			result.retired = append(result.retired, existing)
		}
	}
	if updated.SharedProxyListenAddr != "" {
		if currentShared != nil && currentShared.listenAddr == updated.SharedProxyListenAddr &&
			currentShared.certFile == updated.ProxyTLSCertFile && currentShared.keyFile == updated.ProxyTLSKeyFile &&
			currentShared.tlsTerminated == updated.ProxyTLSTerminated && currentShared.localTLS == updated.LocalTLS {
			if currentShared.localCertificates != nil {
				if err := currentShared.localCertificates.EnsureHosts(localTLSHosts(updated)); err != nil {
					result.rollback()
					return nil, fmt.Errorf("update local certificate names: %w", err)
				}
			}
			result.sharedNext = currentShared
		} else {
			if currentShared != nil && currentShared.listenAddr == updated.SharedProxyListenAddr {
				result.rollback()
				return nil, errors.New("shared proxy transport configuration changed on the same address; restart the manager to apply it")
			}
			listener, err := s.startSharedProxyListener(updated)
			if err != nil {
				result.rollback()
				return nil, fmt.Errorf("start shared proxy: %w", err)
			}
			result.sharedNext = listener
			result.sharedStarted = listener
		}
	}
	if currentShared != nil && result.sharedNext != currentShared {
		result.sharedRetired = currentShared
	}
	return result, nil
}

func (r *proxyListenerReconcile) rollback() {
	if r == nil {
		return
	}
	for _, listener := range r.started {
		closeProxyListener(listener)
	}
	closeSharedProxyListener(r.sharedStarted)
}

func (r *proxyListenerReconcile) commit(s *Server) {
	if r == nil {
		return
	}
	s.proxyMu.Lock()
	listenersStarted := s.proxyListenersStarted
	if listenersStarted {
		s.proxyListeners = r.next
		s.sharedProxyListener = r.sharedNext
	}
	s.proxyMu.Unlock()
	if !listenersStarted {
		r.rollback()
		return
	}
	for _, listener := range r.retired {
		closeProxyListener(listener)
	}
	closeSharedProxyListener(r.sharedRetired)
}

func proxyURLScheme(rawURL string) string {
	parsed, _ := url.Parse(rawURL)
	return strings.ToLower(parsed.Scheme)
}

func (s *Server) proxyIsListening(id string) bool {
	s.proxyMu.Lock()
	_, ok := s.proxyListeners[id]
	shared := s.sharedProxyListener != nil
	s.proxyMu.Unlock()
	if ok {
		return true
	}
	if !shared {
		return false
	}
	instance, exists := s.currentConfig().Gateways[id]
	return exists && instance.ProxyPublicURL != ""
}
