package service

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"
)

func authCall(s *Server, method, path, body string, cookie *http.Cookie) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, path, strings.NewReader(body))
	r.Header.Set("Origin", s.currentConfig().PublicURL)
	r.Header.Set("Content-Type", "application/json")
	if cookie != nil {
		r.AddCookie(cookie)
	}
	w := httptest.NewRecorder()
	s.ServeHTTP(w, r)
	return w
}

func loginCookie(t *testing.T, s *Server) *http.Cookie {
	t.Helper()
	w := authCall(s, "POST", "/auth/v1/session", `{"username":"admin","password":"test-password"}`, nil)
	if w.Code != http.StatusOK {
		t.Fatalf("login: %d %s", w.Code, w.Body.String())
	}
	cookies := w.Result().Cookies()
	if len(cookies) != 1 {
		t.Fatalf("expected one login cookie, got %d", len(cookies))
	}
	return cookies[0]
}

func TestBrowserLoginExpiryAndLogout(t *testing.T) {
	s := newTestServer(t, &fakeGateway{baseURL: "https://localhost:5680"}, "api-secret")
	now := time.Date(2026, 9, 8, 12, 0, 0, 0, time.UTC)
	s.now = func() time.Time { return now }
	for _, body := range []string{`{"username":"admin","password":"wrong"}`, `{"username":"wrong","password":"test-password"}`} {
		if w := authCall(s, "POST", "/auth/v1/session", body, nil); w.Code != 401 || len(w.Result().Cookies()) != 0 {
			t.Fatalf("invalid credentials: %d", w.Code)
		}
	}
	cookie := loginCookie(t, s)
	if !cookie.HttpOnly || cookie.SameSite != http.SameSiteStrictMode || cookie.Domain != "" || cookie.Secure || cookie.MaxAge != 1800 || !cookie.Expires.Equal(now.Add(30*time.Minute)) {
		t.Fatalf("cookie properties: %#v", cookie)
	}
	now = now.Add(29 * time.Minute)
	if w := authCall(s, "GET", "/management/v1/config", "", cookie); w.Code != 200 || strings.Contains(w.Body.String(), "test-password") || strings.Contains(w.Body.String(), "api-secret") {
		t.Fatalf("config must be authorized and redacted: %d", w.Code)
	}
	now = now.Add(time.Minute)
	for _, path := range []string{"/management/v1/config", "/auth/v1/session"} {
		if w := authCall(s, "GET", path, "", cookie); w.Code != 401 {
			t.Fatalf("expired session accepted at %s", path)
		}
	}
	cookie = loginCookie(t, s)
	if w := authCall(s, "DELETE", "/auth/v1/session", "", cookie); w.Code != 200 || w.Result().Cookies()[0].MaxAge != -1 {
		t.Fatal("logout did not expire cookie")
	}
	if w := authCall(s, "GET", "/management/v1/config", "", cookie); w.Code != 401 {
		t.Fatal("logged-out session still works")
	}
}

func TestBrowserCustomTTLAndSecureCookie(t *testing.T) {
	s := newTestServer(t, &fakeGateway{}, "")
	s.config.PublicURL = "https://manager.test"
	s.config.SessionTTLMinutes = 7
	cookie := loginCookie(t, s)
	if !cookie.Secure || cookie.MaxAge != 420 {
		t.Fatalf("HTTPS/TTL configuration not respected: %#v", cookie)
	}
	replacement, err := newServer(s.managers, nil, s.configPath, s.currentConfig())
	if err != nil {
		t.Fatal(err)
	}
	if w := authCall(replacement, "GET", "/auth/v1/session", "", cookie); w.Code != 401 {
		t.Fatal("session survived restart")
	}
}

func TestBrowserOriginAndAPICredentialSeparation(t *testing.T) {
	s := newTestServer(t, &fakeGateway{}, "api-secret")
	cookie := loginCookie(t, s)
	for _, origin := range []string{"", "null", "https://evil.test", "http://manager.test.evil.test", "http://manager.test/"} {
		for _, path := range []string{"/auth/v1/session", "/auth/v1/api-token", "/management/v1/gateways/primary/start"} {
			r := httptest.NewRequest("POST", path, strings.NewReader(`{"username":"admin","password":"test-password"}`))
			r.Header.Set("Origin", origin)
			r.Header.Set("Content-Type", "application/json")
			r.AddCookie(cookie)
			w := httptest.NewRecorder()
			s.ServeHTTP(w, r)
			if w.Code != 401 && w.Code != 403 {
				t.Fatalf("cross-origin mutation accepted: %s %s %d", origin, path, w.Code)
			}
		}
	}
	for _, header := range []string{"Bearer wrong", "Basic YWRtaW46dGVzdC1wYXNzd29yZA=="} {
		r := httptest.NewRequest("GET", "/management/v1/config", nil)
		r.AddCookie(cookie)
		r.Header.Set("Authorization", header)
		w := httptest.NewRecorder()
		s.ServeHTTP(w, r)
		if w.Code != 401 {
			t.Fatal("explicit bad API auth fell back to cookie")
		}
	}
	for _, path := range []string{"/auth/v1/session", "/auth/v1/api-token"} {
		r := httptest.NewRequest("POST", path, nil)
		r.Header.Set("Authorization", "Bearer api-secret")
		r.Header.Set("Origin", s.config.PublicURL)
		w := httptest.NewRecorder()
		s.ServeHTTP(w, r)
		if w.Code == 200 {
			t.Fatal("API token granted browser authentication/token generation")
		}
	}
	r := httptest.NewRequest("POST", "/management/v1/gateways/primary/start", nil)
	r.Header.Set("Authorization", "Bearer api-secret")
	w := httptest.NewRecorder()
	s.ServeHTTP(w, r)
	if w.Code != 200 {
		t.Fatalf("API request without Origin failed: %d", w.Code)
	}
}

func TestGeneratedAPITokenRotationRevocationAndPersistence(t *testing.T) {
	s := newTestServer(t, &fakeGateway{baseURL: "https://localhost:5680"}, "")
	if w := authCall(s, "GET", "/management/v1/config", "", nil); w.Code != 401 {
		t.Fatal("blank API token enabled anonymous access")
	}
	cookie := loginCookie(t, s)
	generate := func() string {
		t.Helper()
		w := authCall(s, "POST", "/auth/v1/api-token", "", cookie)
		if w.Code != 200 || w.Header().Get("Cache-Control") != "no-store" {
			t.Fatalf("generate: %d", w.Code)
		}
		var data struct {
			Token string `json:"api_token"`
		}
		if err := json.Unmarshal(w.Body.Bytes(), &data); err != nil {
			t.Fatal(err)
		}
		if len(data.Token) != 43 {
			t.Fatal("expected 256-bit token")
		}
		return data.Token
	}
	check := func(token string, want int) {
		t.Helper()
		r := httptest.NewRequest("GET", "/management/v1/config", nil)
		r.Header.Set("Authorization", "Bearer "+token)
		w := httptest.NewRecorder()
		s.ServeHTTP(w, r)
		if w.Code != want {
			t.Fatalf("API auth status=%d want=%d", w.Code, want)
		}
	}
	first := generate()
	check(first, 200)
	data, err := os.ReadFile(s.configPath)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), first) {
		t.Fatal("token not persisted")
	}
	info, err := os.Stat(s.configPath)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0600 {
		t.Fatal("unsafe config permissions")
	}
	replacement, err := newServer(s.managers, nil, s.configPath, s.currentConfig())
	if err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest("GET", "/management/v1/config", nil)
	r.Header.Set("Authorization", "Bearer "+first)
	w := httptest.NewRecorder()
	replacement.ServeHTTP(w, r)
	if w.Code != 200 {
		t.Fatal("token lost on restart")
	}
	second := generate()
	if first == second {
		t.Fatal("token not rotated")
	}
	check(first, 401)
	check(second, 200)
	if w := authCall(s, "PUT", "/management/v1/config", `{"api_token":"user-chosen-token"}`, cookie); w.Code != 400 {
		t.Fatal("legacy token assignment accepted")
	}
	if w := authCall(s, "DELETE", "/auth/v1/api-token", "", cookie); w.Code != 200 {
		t.Fatal("token revocation failed")
	}
	check(second, 401)
	if w := authCall(s, "GET", "/management/v1/config", "", cookie); w.Code != 200 {
		t.Fatal("revocation ended browser session")
	}
}

func TestTokenSaveFailureKeepsOldCredential(t *testing.T) {
	s := newTestServer(t, &fakeGateway{}, "old-secret")
	cookie := loginCookie(t, s)
	if err := os.Mkdir(s.configPath, 0700); err != nil {
		t.Fatal(err)
	}
	w := authCall(s, "POST", "/auth/v1/api-token", "", cookie)
	if w.Code != 500 || s.currentConfig().APIToken != "old-secret" {
		t.Fatal("failed save changed active credential")
	}
}

func TestGatewayBrowserGrantBoundToManagerSession(t *testing.T) {
	s := newTestServer(t, &fakeGateway{baseURL: "https://localhost:5680"}, "api-secret")
	instance := s.config.Gateways["primary"]
	instance.ProxyListenAddr = "127.0.0.1:18081"
	instance.ProxyPublicURL = "http://primary.test:18081"
	instance.ProxyToken = "instance-secret"
	s.config.Gateways["primary"] = instance
	now := time.Now()
	s.now = func() time.Time { return now }
	cookie := loginCookie(t, s)
	now = now.Add(29 * time.Minute)
	issue := func() string {
		t.Helper()
		w := authCall(s, "POST", "/management/v1/gateways/primary/login-ticket", "", cookie)
		if w.Code != 201 {
			t.Fatalf("ticket: %d", w.Code)
		}
		var data struct {
			URL string `json:"url"`
		}
		_ = json.Unmarshal(w.Body.Bytes(), &data)
		return data.URL
	}
	raw := issue()
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	w := httptest.NewRecorder()
	s.consumeDedicatedLoginTicket(w, httptest.NewRequest("GET", u.String(), nil), "primary")
	if w.Code != 302 {
		t.Fatalf("ticket consume: %d", w.Code)
	}
	grant := w.Result().Cookies()[0]
	if grant.MaxAge != 60 {
		t.Fatalf("proxy grant extends manager deadline: %d", grant.MaxAge)
	}
	r := httptest.NewRequest("GET", "/v1/api/tickle", nil)
	r.AddCookie(grant)
	if !s.authorizedProxy(r, "primary") {
		t.Fatal("valid proxy grant rejected")
	}
	w = httptest.NewRecorder()
	s.consumeDedicatedLoginTicket(w, httptest.NewRequest("GET", raw, nil), "primary")
	if w.Code != 401 {
		t.Fatal("ticket reused")
	}
	pending := issue()
	authCall(s, "DELETE", "/auth/v1/session", "", cookie)
	if s.authorizedProxy(r, "primary") {
		t.Fatal("proxy grant survived manager logout")
	}
	w = httptest.NewRecorder()
	s.consumeDedicatedLoginTicket(w, httptest.NewRequest("GET", pending, nil), "primary")
	if w.Code != 401 {
		t.Fatal("pending ticket survived manager logout")
	}
	r = httptest.NewRequest("GET", "/v1/api/tickle", nil)
	r.Header.Set("Authorization", "Bearer instance-secret")
	if !s.authorizedProxy(r, "primary") {
		t.Fatal("manager logout revoked external instance token")
	}
	r.Header.Set("Authorization", "Bearer api-secret")
	if s.authorizedProxy(r, "primary") {
		t.Fatal("manager token accessed instance")
	}
	r.SetBasicAuth("gateway", "instance-secret")
	if s.authorizedProxy(r, "primary") {
		t.Fatal("legacy Basic accepted")
	}
	instance.ProxyToken = ""
	s.config.Gateways["primary"] = instance
	r = httptest.NewRequest("GET", "/v1/api/tickle?token=api-secret", nil)
	if s.authorizedProxy(r, "primary") {
		t.Fatal("blank instance token opened anonymous access")
	}
}

func TestLoginRateLimit(t *testing.T) {
	s := newTestServer(t, &fakeGateway{}, "")
	now := time.Now()
	s.now = func() time.Time { return now }
	for i := 0; i < 20; i++ {
		if w := authCall(s, "POST", "/auth/v1/session", `{"username":"admin","password":"wrong"}`, nil); w.Code != 401 {
			t.Fatalf("attempt %d = %d", i, w.Code)
		}
	}
	if w := authCall(s, "POST", "/auth/v1/session", `{"username":"admin","password":"test-password"}`, nil); w.Code != 429 {
		t.Fatal("login not rate limited")
	}
	now = now.Add(time.Minute)
	loginCookie(t, s)
}

func TestExternalTokenOutlivesBrowserLogin(t *testing.T) {
	s := newTestServer(t, &fakeGateway{}, "external-secret")
	now := time.Now()
	s.now = func() time.Time { return now }
	cookie := loginCookie(t, s)
	now = now.Add(30 * time.Minute)
	if w := authCall(s, "GET", "/auth/v1/session", "", cookie); w.Code != 401 {
		t.Fatal("browser did not expire")
	}
	r := httptest.NewRequest("GET", "/management/v1/config", nil)
	r.Header.Set("Authorization", "Bearer external-secret")
	w := httptest.NewRecorder()
	s.ServeHTTP(w, r)
	if w.Code != 200 {
		t.Fatal("browser expiry revoked API token")
	}
	cookie = loginCookie(t, s)
	authCall(s, "DELETE", "/auth/v1/session", "", cookie)
	w = httptest.NewRecorder()
	s.ServeHTTP(w, r)
	if w.Code != 200 {
		t.Fatal("browser logout revoked API token")
	}
}

func TestConfigSavePreservesManagerLoginAndStartupCredentials(t *testing.T) {
	s := newTestServer(t, &fakeGateway{baseURL: "https://localhost:5680"}, "api-secret")
	cookie := loginCookie(t, s)
	for _, body := range []string{`{"username":"other"}`, `{"password":"other"}`, `{"session_ttl_minutes":60}`} {
		if w := authCall(s, "PUT", "/management/v1/config", body, cookie); w.Code != 400 {
			t.Fatalf("startup credential mutation accepted: %s", body)
		}
	}
	body, err := json.Marshal(map[string]any{"gateways": s.currentConfig().Gateways})
	if err != nil {
		t.Fatal(err)
	}
	if w := authCall(s, "PUT", "/management/v1/config", string(body), cookie); w.Code != 200 {
		t.Fatalf("config save: %d %s", w.Code, w.Body.String())
	}
	if w := authCall(s, "GET", "/auth/v1/session", "", cookie); w.Code != 200 {
		t.Fatal("ordinary config save revoked manager login")
	}
}
