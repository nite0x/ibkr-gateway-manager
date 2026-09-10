package service

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"math"
	"mime"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/nite0x/ibkr-gateway-manager/internal/appconfig"
)

type loginTicket struct {
	Owner          string
	SessionExpires time.Time
	GatewayID      string
	Expires        time.Time
}

type browserSession struct {
	Owner     string
	GatewayID string
	Expires   time.Time
}

func (s *Server) authorizedAPI(r *http.Request) bool {
	token := strings.TrimSpace(s.currentConfig().APIToken)
	if token == "" {
		return false
	}
	provided, ok := bearerToken(r)
	return ok && secureTokenEqual(provided, token)
}

func (s *Server) authorizedProxy(r *http.Request, id string) bool {
	instance, ok := s.currentConfig().Gateways[id]
	if !ok {
		return false
	}
	token := strings.TrimSpace(instance.ProxyToken)
	if r.Header.Get("Authorization") != "" {
		provided, ok := bearerToken(r)
		return ok && token != "" && secureTokenEqual(provided, token)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.cleanupLocked()
	for _, name := range []string{browserGatewaySessionCookie(id)} {
		cookie, err := r.Cookie(name)
		if err != nil {
			continue
		}
		session, ok := s.sessions[cookie.Value]
		if ok && session.GatewayID == id && session.Expires.After(s.now()) && s.ownerValidLocked(session.Owner) {
			return true
		}
	}
	return false
}

func bearerToken(r *http.Request) (string, bool) {
	const prefix = "Bearer "
	header := strings.TrimSpace(r.Header.Get("Authorization"))
	if len(header) <= len(prefix) || !strings.EqualFold(header[:len(prefix)], prefix) {
		return "", false
	}
	return strings.TrimSpace(header[len(prefix):]), true
}

func secureTokenEqual(provided, expected string) bool {
	left, right := sha256.Sum256([]byte(provided)), sha256.Sum256([]byte(expected))
	return subtle.ConstantTimeCompare(left[:], right[:]) == 1
}

func (s *Server) issueLoginTicket(w http.ResponseWriter, r *http.Request, id string) {
	cfg := s.currentConfig()
	instance, ok := cfg.Gateways[id]
	if !ok || instance.ProxyPublicURL == "" || (cfg.SharedProxyListenAddr == "" && instance.ProxyListenAddr == "") {
		writeJSON(w, http.StatusConflict, map[string]any{"error": "gateway proxy is not configured"})
		return
	}
	ticket, err := randomToken()
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
		return
	}
	owner, parent, authenticated := s.managerSession(r)
	if r.Header.Get("Authorization") == "" && !authenticated {
		writeJSON(w, http.StatusUnauthorized, map[string]any{"error": "session expired"})
		return
	}
	expires := s.now().Add(time.Duration(cfg.SessionTTLMinutes) * time.Minute)
	if owner != "" {
		expires = parent.Expires
	}
	s.mu.Lock()
	s.cleanupLocked()
	s.tickets[ticket] = loginTicket{Owner: owner, SessionExpires: expires, GatewayID: id, Expires: s.now().Add(2 * time.Minute)}
	s.mu.Unlock()
	writeJSON(w, http.StatusCreated, map[string]any{
		"gateway_id": id, "url": instance.ProxyPublicURL + dedicatedLoginPath + "?ticket=" + url.QueryEscape(ticket), "expires_in_seconds": 120,
	})
}

func (s *Server) consumeDedicatedLoginTicket(w http.ResponseWriter, r *http.Request, id string) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Referrer-Policy", "no-referrer")
	sessionValue, ok := s.consumeTicket(w, r, id)
	if !ok {
		return
	}
	cfg := s.currentConfig()
	instance, exists := cfg.Gateways[id]
	if !exists || instance.ProxyPublicURL == "" {
		writeJSON(w, http.StatusNotFound, map[string]any{"error": "gateway proxy not configured"})
		return
	}
	secure := strings.HasPrefix(strings.ToLower(instance.ProxyPublicURL), "https://")
	s.mu.Lock()
	expires := s.sessions[sessionValue].Expires
	s.mu.Unlock()
	http.SetCookie(w, &http.Cookie{
		Name: browserGatewaySessionCookie(id), Value: sessionValue, Path: "/",
		HttpOnly: true, Secure: secure, SameSite: http.SameSiteLaxMode, MaxAge: int(math.Ceil(expires.Sub(s.now()).Seconds())), Expires: expires,
	})
	http.Redirect(w, r, "/sso/Login", http.StatusFound)
}

func (s *Server) consumeTicket(w http.ResponseWriter, r *http.Request, expectedGatewayID string) (string, bool) {
	ticketValue := r.URL.Query().Get("ticket")
	s.mu.Lock()
	defer s.mu.Unlock()
	ticket, ok := s.tickets[ticketValue]
	delete(s.tickets, ticketValue)
	if !ok || !ticket.Expires.After(s.now()) || (expectedGatewayID != "" && ticket.GatewayID != expectedGatewayID) || !s.ownerValidLocked(ticket.Owner) || !ticket.SessionExpires.After(s.now()) {
		writeJSON(w, http.StatusUnauthorized, map[string]any{"error": "invalid or expired login ticket"})
		return "", false
	}
	sessionValue, err := randomToken()
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
		return "", false
	}
	s.sessions[sessionValue] = browserSession{Owner: ticket.Owner, GatewayID: ticket.GatewayID, Expires: ticket.SessionExpires}
	return sessionValue, true
}

func (s *Server) cleanupLocked() {
	now := s.now()
	for key, ticket := range s.tickets {
		if !ticket.Expires.After(now) {
			delete(s.tickets, key)
		}
	}
	for key, session := range s.sessions {
		if !session.Expires.After(now) {
			delete(s.sessions, key)
		}
	}
}

func encodeGatewayID(id string) string { return base64.RawURLEncoding.EncodeToString([]byte(id)) }

func browserGatewaySessionCookie(id string) string {
	return browserSessionCookie + "_" + encodeGatewayID(id)
}

func randomToken() (string, error) {
	data := make([]byte, 32)
	if _, err := rand.Read(data); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(data), nil
}

// A gateway browser grant cannot outlive or survive logout of its manager login.
func (s *Server) ownerValidLocked(owner string) bool {
	if owner == "" {
		return true
	}
	parent, ok := s.sessions[owner]
	return ok && parent.GatewayID == "" && parent.Expires.After(s.now())
}

func (s *Server) managerSession(r *http.Request) (string, browserSession, bool) {
	cookie, err := r.Cookie(browserSessionCookie)
	if err != nil {
		return "", browserSession{}, false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.cleanupLocked()
	session, ok := s.sessions[cookie.Value]
	if !ok || session.GatewayID != "" {
		return "", browserSession{}, false
	}
	return cookie.Value, session, true
}

func (s *Server) sameManagerOrigin(r *http.Request) bool {
	origin, err := url.Parse(r.Header.Get("Origin"))
	expected, _ := url.Parse(s.currentConfig().PublicURL)
	return err == nil && expected != nil && origin.User == nil && origin.Path == "" && origin.RawQuery == "" && origin.Fragment == "" && sameOrigin(origin, expected)
}

func (s *Server) authorizedManagement(r *http.Request) bool {
	// Explicit API credentials never fall back to a browser cookie.
	if r.Header.Get("Authorization") != "" {
		return s.authorizedAPI(r)
	}
	_, _, ok := s.managerSession(r)
	return ok && (r.Method == http.MethodGet || r.Method == http.MethodHead || s.sameManagerOrigin(r))
}

func (s *Server) setManagerCookie(w http.ResponseWriter, value string, expires time.Time, maxAge int) {
	http.SetCookie(w, &http.Cookie{Name: browserSessionCookie, Value: value, Path: "/",
		HttpOnly: true, Secure: strings.HasPrefix(s.currentConfig().PublicURL, "https://"),
		SameSite: http.SameSiteStrictMode, Expires: expires, MaxAge: maxAge})
}

func (s *Server) serveAuth(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if r.Method != http.MethodGet && !s.sameManagerOrigin(r) {
		writeJSON(w, http.StatusForbidden, map[string]any{"error": "same-origin request required"})
		return
	}
	if r.URL.Path == "/auth/v1/session" && r.Method == http.MethodPost {
		if !s.allowLoginAttempt(r) {
			w.Header().Set("Retry-After", "60")
			writeJSON(w, http.StatusTooManyRequests, map[string]any{"error": "too many login attempts; retry in one minute"})
			return
		}
		media, _, _ := mime.ParseMediaType(r.Header.Get("Content-Type"))
		if media != "application/json" {
			writeJSON(w, http.StatusUnsupportedMediaType, map[string]any{"error": "application/json required"})
			return
		}
		var credentials struct {
			Username string `json:"username"`
			Password string `json:"password"`
		}
		decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 8192))
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&credentials); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid login request"})
			return
		}
		cfg := s.currentConfig()
		userOK := secureTokenEqual(credentials.Username, cfg.Username)
		passwordOK := secureTokenEqual(credentials.Password, cfg.Password)
		if !userOK || !passwordOK {
			writeJSON(w, http.StatusUnauthorized, map[string]any{"error": "用户名或密码错误"})
			return
		}
		value, err := randomToken()
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]any{"error": "could not create session"})
			return
		}
		expires := s.now().Add(time.Duration(cfg.SessionTTLMinutes) * time.Minute)
		old, _, _ := s.managerSession(r)
		s.mu.Lock()
		s.cleanupLocked()
		if old != "" {
			s.revokeManagerSessionLocked(old)
		}
		s.sessions[value] = browserSession{Expires: expires}
		s.mu.Unlock()
		s.setManagerCookie(w, value, expires, cfg.SessionTTLMinutes*60)
		writeJSON(w, http.StatusOK, map[string]any{"username": cfg.Username, "expires_at": expires})
		return
	}
	value, session, ok := s.managerSession(r)
	if !ok {
		writeJSON(w, http.StatusUnauthorized, map[string]any{"error": "请登录，或登录已过期"})
		return
	}
	switch {
	case r.URL.Path == "/auth/v1/session" && r.Method == http.MethodGet:
		writeJSON(w, http.StatusOK, map[string]any{"username": s.currentConfig().Username, "expires_at": session.Expires})
	case r.URL.Path == "/auth/v1/session" && r.Method == http.MethodDelete:
		s.mu.Lock()
		s.revokeManagerSessionLocked(value)
		s.mu.Unlock()
		s.setManagerCookie(w, "", time.Unix(1, 0), -1)
		writeJSON(w, http.StatusOK, map[string]any{"status": "logged_out"})
	case r.URL.Path == "/auth/v1/api-token" && (r.Method == http.MethodPost || r.Method == http.MethodDelete):
		s.opMu.Lock()
		defer s.opMu.Unlock()
		if s.closing {
			writeJSON(w, http.StatusServiceUnavailable, map[string]any{"error": "manager is shutting down"})
			return
		}
		if _, _, valid := s.managerSession(r); !valid {
			writeJSON(w, http.StatusUnauthorized, map[string]any{"error": "session expired"})
			return
		}
		token := ""
		if r.Method == http.MethodPost {
			var err error
			token, err = randomToken()
			if err != nil {
				writeJSON(w, http.StatusInternalServerError, map[string]any{"error": "could not generate token"})
				return
			}
		}
		cfg := s.currentConfig()
		cfg.APIToken = token
		if err := appconfig.Save(s.configPath, cfg); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]any{"error": "could not save API token"})
			return
		}
		s.mu.Lock()
		s.config.APIToken = token
		s.mu.Unlock()
		writeJSON(w, http.StatusOK, map[string]any{"api_token": token})
	default:
		writeJSON(w, http.StatusNotFound, map[string]any{"error": "not found"})
	}
}

func (s *Server) revokeManagerSessionLocked(value string) {
	delete(s.sessions, value)
	for token, session := range s.sessions {
		if session.Owner == value {
			delete(s.sessions, token)
		}
	}
	for token, ticket := range s.tickets {
		if ticket.Owner == value {
			delete(s.tickets, token)
		}
	}
}

// Limit login attempts by socket peer; never trust client-supplied forwarded IPs.
// Behind a reverse proxy, requests share that proxy's limit.
type loginAttemptWindow struct {
	Count   int
	Expires time.Time
}

func (s *Server) allowLoginAttempt(r *http.Request) bool {
	peer, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		peer = r.RemoteAddr
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	if s.loginAttempts == nil {
		s.loginAttempts = make(map[string]loginAttemptWindow)
	}
	for key, window := range s.loginAttempts {
		if !window.Expires.After(now) {
			delete(s.loginAttempts, key)
		}
	}
	window, exists := s.loginAttempts[peer]
	if !exists {
		if len(s.loginAttempts) >= 4096 {
			return false
		}
		window.Expires = now.Add(time.Minute)
	}
	if window.Count >= 20 {
		return false
	}
	window.Count++
	s.loginAttempts[peer] = window
	return true
}
