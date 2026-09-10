package service

import (
	"context"
	"crypto/tls"
	"fmt"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"time"
)

type proxyRequestContext struct {
	ResetUpstream        bool
	StaleUpstreamCookies []string
}

type proxyRequestContextKey struct{}

// ServeGatewayProxy serves a complete Gateway origin at / for one instance.
// This avoids the path rewriting assumptions in the IBKR login application.
func (s *Server) ServeGatewayProxy(id string, w http.ResponseWriter, r *http.Request) {
	if r.URL.Path == dedicatedLoginPath && r.Method == http.MethodGet {
		s.consumeDedicatedLoginTicket(w, r, id)
		return
	}
	if !s.authorizedProxy(r, id) {
		w.Header().Set("WWW-Authenticate", "Bearer")
		writeJSON(w, http.StatusUnauthorized, map[string]any{"error": "unauthorized"})
		return
	}
	s.registryMu.RLock()
	proxy, ok := s.dedicatedProxies[id]
	s.registryMu.RUnlock()
	if !ok {
		writeJSON(w, http.StatusNotFound, map[string]any{"error": "gateway proxy not configured"})
		return
	}
	// A dedicated listener is already a complete origin. Keep IBKR cookie names
	// intact because the Dispatcher JavaScript reads cookies such as
	// JSESSIONID/x-sess-uuid by name. Deploy multiple browser-facing instances
	// on separate hostnames to obtain browser cookie isolation.
	s.serveProxy(w, r, proxy)
}

func (s *Server) serveProxy(w http.ResponseWriter, r *http.Request, proxy *httputil.ReverseProxy) {
	request := r.Clone(r.Context())
	metadata := proxyRequestContext{}
	if r.Method == http.MethodGet && request.URL.Path == "/sso/Login" {
		metadata.ResetUpstream = true
		for _, cookie := range r.Cookies() {
			if isManagerCookie(cookie.Name) {
				continue
			}
			if !strings.HasPrefix(cookie.Name, upstreamCookieBase) {
				metadata.StaleUpstreamCookies = append(metadata.StaleUpstreamCookies, cookie.Name)
			}
		}
	}
	request = request.WithContext(context.WithValue(request.Context(), proxyRequestContextKey{}, metadata))
	proxy.ServeHTTP(w, request)
}

func newGatewayProxy(rawTarget, rawPublicURL string, onLoginComplete func()) (*httputil.ReverseProxy, error) {
	target, err := url.Parse(rawTarget)
	if err != nil {
		return nil, fmt.Errorf("parse gateway target: %w", err)
	}
	publicURL, err := url.Parse(rawPublicURL)
	if err != nil {
		return nil, fmt.Errorf("parse public URL: %w", err)
	}
	proxy := httputil.NewSingleHostReverseProxy(target)
	proxy.Transport = &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12, InsecureSkipVerify: true}}
	originalDirector := proxy.Director
	proxy.Director = func(req *http.Request) {
		originalDirector(req)
		prepareGatewaySSOScript(req)
		req.Host = target.Host
		rewriteGatewayRequestOrigin(req, target, publicURL)
		req.Header.Del("Authorization")
		cookies := req.Cookies()
		req.Header.Del("Cookie")
		metadata, _ := req.Context().Value(proxyRequestContextKey{}).(proxyRequestContext)
		for _, cookie := range cookies {
			if isManagerCookie(cookie.Name) {
				continue
			}
			if metadata.ResetUpstream {
				continue
			}
			if strings.HasPrefix(cookie.Name, upstreamCookieBase) {
				continue
			}
			req.AddCookie(cookie)
		}
		req.Header.Del("Forwarded")
		req.Header.Del("X-Forwarded-For")
		req.Header.Del("X-Forwarded-Host")
		req.Header.Del("X-Forwarded-Proto")
	}
	proxy.ModifyResponse = func(resp *http.Response) error {
		if err := observeGatewayLogin(resp, onLoginComplete); err != nil {
			return err
		}
		metadata, _ := resp.Request.Context().Value(proxyRequestContextKey{}).(proxyRequestContext)
		rewriteGatewayCookies(resp, publicURL.Scheme == "https")
		expireStaleGatewayCookies(resp, publicURL.Scheme == "https", metadata)
		rewriteGatewayLocation(resp, target, publicURL)
		return rewriteGatewaySSOScript(resp)
	}
	proxy.ErrorHandler = func(w http.ResponseWriter, _ *http.Request, err error) {
		writeJSON(w, http.StatusBadGateway, map[string]any{"error": "gateway unavailable", "details": err.Error()})
	}
	return proxy, nil
}

// IBKR validates the browser origin during the SSO exchange. A transparent
// listener has a different port from the private Gateway, so forward the
// equivalent private Origin and Referer instead of leaking the public proxy
// origin upstream.
func rewriteGatewayRequestOrigin(req *http.Request, target, publicURL *url.URL) {
	targetOrigin := target.Scheme + "://" + target.Host
	if origin := strings.TrimSpace(req.Header.Get("Origin")); origin != "" && origin != "null" {
		if parsed, err := url.Parse(origin); err == nil && sameOrigin(parsed, publicURL) {
			req.Header.Set("Origin", targetOrigin)
		}
	}
	if referer := strings.TrimSpace(req.Header.Get("Referer")); referer != "" {
		if parsed, err := url.Parse(referer); err == nil && sameOrigin(parsed, publicURL) {
			parsed.Scheme = target.Scheme
			parsed.Host = target.Host
			req.Header.Set("Referer", parsed.String())
		}
	}
}

func sameOrigin(left, right *url.URL) bool {
	return strings.EqualFold(left.Scheme, right.Scheme) && strings.EqualFold(left.Host, right.Host)
}

func expireStaleGatewayCookies(resp *http.Response, secureOrigin bool, metadata proxyRequestContext) {
	if !metadata.ResetUpstream || len(metadata.StaleUpstreamCookies) == 0 {
		return
	}
	refreshed := make(map[string]struct{})
	for _, cookie := range resp.Cookies() {
		refreshed[cookie.Name] = struct{}{}
	}
	for _, name := range metadata.StaleUpstreamCookies {
		if _, ok := refreshed[name]; ok {
			continue
		}
		resp.Header.Add("Set-Cookie", (&http.Cookie{
			Name: name, Value: "", Path: "/", HttpOnly: true, Secure: secureOrigin,
			MaxAge: -1, Expires: time.Unix(1, 0), SameSite: http.SameSiteLaxMode,
		}).String())
	}
}

func rewriteGatewayCookies(resp *http.Response, secureOrigin bool) {
	cookies := resp.Cookies()
	if len(cookies) == 0 {
		return
	}
	resp.Header.Del("Set-Cookie")
	for _, cookie := range cookies {
		if isManagerCookie(cookie.Name) {
			continue
		}
		cookie.Domain = ""
		cookie.Secure = secureOrigin
		if !secureOrigin && cookie.SameSite == http.SameSiteNoneMode {
			cookie.SameSite = http.SameSiteLaxMode
		}
		resp.Header.Add("Set-Cookie", cookie.String())
	}
}

func rewriteGatewayLocation(resp *http.Response, target, publicURL *url.URL) {
	location := strings.TrimSpace(resp.Header.Get("Location"))
	if location == "" {
		return
	}
	parsed, err := url.Parse(location)
	if err != nil {
		return
	}
	if parsed.IsAbs() || parsed.Host != "" {
		if !strings.EqualFold(parsed.Host, target.Host) {
			return
		}
		parsed.Scheme, parsed.Host = publicURL.Scheme, publicURL.Host
	}
	resp.Header.Set("Location", parsed.String())
}

func isManagerCookie(name string) bool {
	return name == browserSessionCookie || strings.HasPrefix(name, browserSessionCookie+"_")
}
