package service

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/nite0x/ibkr-gateway-manager/gateway"
	"github.com/nite0x/ibkr-gateway-manager/internal/appconfig"
)

type fakeGateway struct {
	baseURL string
	status  gateway.GatewayStatus
	started int
	stopped int
}

func (f *fakeGateway) Status() gateway.GatewayStatus { return f.status }
func (f *fakeGateway) BaseURL() string               { return f.baseURL }
func (f *fakeGateway) StartGateway(context.Context) error {
	f.started++
	return nil
}
func (f *fakeGateway) StopGateway(bool) error           { f.stopped++; return nil }
func (f *fakeGateway) Reconnect() error                 { return nil }
func (f *fakeGateway) Upgrade(context.Context) error    { return nil }
func (f *fakeGateway) Rollback(context.Context) error   { return nil }
func (f *fakeGateway) Reconfigure(gateway.Config) error { return nil }
func (f *fakeGateway) Shutdown() error                  { return nil }

func TestEmbeddedManagerUI(t *testing.T) {
	handler := newTestServer(t, &fakeGateway{}, "secret")

	request := httptest.NewRequest(http.MethodGet, "/manager/", nil)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("manager status = %d: %s", response.Code, (response.Body.String() + string(managerJS)))
	}
	if contentType := response.Header().Get("Content-Type"); !strings.HasPrefix(contentType, "text/html") {
		t.Fatalf("manager content type = %q", contentType)
	}
	if !strings.Contains((response.Body.String()+string(managerJS)), "IBKR Gateway") || !strings.Contains((response.Body.String()+string(managerJS)), "/management/v1") {
		t.Fatal("manager page is missing its title or API client")
	}
	if !strings.Contains((response.Body.String()+string(managerJS)), "Gateway 数据父目录") ||
		!strings.Contains((response.Body.String()+string(managerJS)), "公开 URL 模板") ||
		!strings.Contains((response.Body.String()+string(managerJS)), "继承全局网络和上游设置") ||
		!strings.Contains((response.Body.String()+string(managerJS)), "共享 HTTPS 入口") {
		t.Fatal("manager page is missing simplified global and per-instance settings")
	}
	if !strings.Contains((response.Body.String()+string(managerJS)), `input.type = "text"`) ||
		!strings.Contains((response.Body.String()+string(managerJS)), "已生成新密钥并选中") {
		t.Fatal("manager page must reveal and confirm a regenerated proxy token")
	}
	if !strings.Contains((response.Body.String()+string(managerJS)), "重启 Gateway") ||
		!strings.Contains((response.Body.String()+string(managerJS)), "重启后将检查会话") {
		t.Fatal("manager page must clearly label and confirm a full Gateway restart")
	}
	if !strings.Contains((response.Body.String()+string(managerJS)), "window.open(\"about:blank\", \"_blank\"") ||
		!strings.Contains((response.Body.String()+string(managerJS)), "gateway.proxy_public_url") ||
		!strings.Contains((response.Body.String()+string(managerJS)), "loginTab.location.replace(ticket.url)") {
		t.Fatal("manager login must open the public proxy ticket URL in a new tab")
	}
	if response.Header().Get("Content-Security-Policy") == "" {
		t.Fatal("manager page is missing its content security policy")
	}

	request = httptest.NewRequest(http.MethodPost, "/manager/", nil)
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusMethodNotAllowed || response.Header().Get("Allow") != "GET, HEAD" {
		t.Fatalf("manager POST = %d, allow = %q", response.Code, response.Header().Get("Allow"))
	}
}

func TestManagementRequiresBearerToken(t *testing.T) {
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {}))
	defer upstream.Close()
	handler := newTestServer(t, &fakeGateway{baseURL: upstream.URL}, "secret")

	request := httptest.NewRequest(http.MethodGet, "/management/v1/gateways/primary/status", nil)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusUnauthorized {
		t.Fatalf("unauthorized status = %d", response.Code)
	}

	request = httptest.NewRequest(http.MethodGet, "/management/v1/gateways/primary/status", nil)
	request.Header.Set("Authorization", "Bearer secret")
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("authorized status = %d: %s", response.Code, response.Body.String())
	}
}

func TestConfigUpdateAppliesGlobalDefaults(t *testing.T) {
	baseDir := t.TempDir()
	cfg := testDefaultConfig(baseDir)
	handler, err := NewRegistry(filepath.Join(baseDir, "config.json"), cfg, func(cfg gateway.Config) Gateway {
		return &fakeGateway{baseURL: cfg.GatewayURL}
	})
	if err != nil {
		t.Fatal(err)
	}
	body, err := json.Marshal(map[string]any{
		"gateway_root_dir":          filepath.Join(baseDir, "instances"),
		"shared_gateway_dir":        filepath.Join(baseDir, "program"),
		"proxy_listen_host":         "127.0.0.1",
		"proxy_public_url_template": "http://localhost:{port}",
		"gateways":                  handler.currentConfig().Gateways,
	})
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodPut, "/management/v1/config", strings.NewReader(string(body)))
	request.Header.Set("Authorization", "Bearer secret")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("update globals = %d: %s", response.Code, response.Body.String())
	}
	updated := handler.currentConfig()
	primary := updated.Gateways[appconfig.DefaultGatewayID]
	if updated.GatewayRootDir != filepath.Join(baseDir, "instances") || primary.GatewayStateDir != filepath.Join(baseDir, "instances", ".instances", appconfig.DefaultGatewayID) || primary.GatewayDir != filepath.Join(baseDir, "program") {
		t.Fatalf("global install root was not applied: %#v", updated)
	}
	if primary.ProxyPublicURL != "http://localhost:18081" || primary.ProxyListenAddr != "127.0.0.1:18081" {
		t.Fatalf("global proxy defaults were not applied: %#v", primary)
	}
}

func TestConfigRedactsAndPreservesProxyToken(t *testing.T) {
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {}))
	defer upstream.Close()
	parsedUpstream, err := url.Parse(upstream.URL)
	if err != nil {
		t.Fatal(err)
	}
	port, err := strconv.Atoi(parsedUpstream.Port())
	if err != nil {
		t.Fatal(err)
	}
	cfg := appconfig.Config{Username: "admin", Password: "test-password", SessionTTLMinutes: 30,
		ListenAddr: "127.0.0.1:8088", PublicURL: "http://manager.test", APIToken: "manager-key",
		Gateways: map[string]appconfig.GatewayInstance{
			"alpha": {
				Config:          gateway.Config{GatewayDir: filepath.Join(t.TempDir(), "alpha"), GatewayPort: port, GatewayURL: upstream.URL},
				ProxyListenAddr: "127.0.0.1:18081", ProxyPublicURL: "http://127.0.0.1:18081", ProxyToken: "alpha-key",
			},
		},
	}
	handler, err := newServer(map[string]Gateway{"alpha": &fakeGateway{baseURL: upstream.URL}}, nil, filepath.Join(t.TempDir(), "config.json"), cfg)
	if err != nil {
		t.Fatal(err)
	}

	request := httptest.NewRequest(http.MethodGet, "/management/v1/config", nil)
	request.Header.Set("Authorization", "Bearer manager-key")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("get config = %d: %s", response.Code, response.Body.String())
	}
	var redacted appconfig.Config
	if err := json.Unmarshal(response.Body.Bytes(), &redacted); err != nil {
		t.Fatal(err)
	}
	if redacted.APIToken != "" || redacted.Gateways["alpha"].ProxyToken != "" {
		t.Fatalf("config leaked a token: %#v", redacted)
	}
	if handler.currentConfig().Gateways["alpha"].ProxyToken != "alpha-key" {
		t.Fatal("redacting the response mutated the live proxy token")
	}

	body, err := json.Marshal(redacted)
	if err != nil {
		t.Fatal(err)
	}
	request = httptest.NewRequest(http.MethodPut, "/management/v1/config", strings.NewReader(string(body)))
	request.Header.Set("Authorization", "Bearer manager-key")
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("save redacted config = %d: %s", response.Code, response.Body.String())
	}
	updated := handler.currentConfig()
	if updated.APIToken != "manager-key" || updated.Gateways["alpha"].ProxyToken != "alpha-key" {
		t.Fatalf("saving redacted config erased a token: %#v", updated)
	}
}

func TestLegacyManagerRoutesAreRemoved(t *testing.T) {
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {}))
	defer upstream.Close()
	handler := newTestServer(t, &fakeGateway{baseURL: upstream.URL}, "secret")
	for _, route := range []struct{ method, path string }{
		{http.MethodGet, "/management/v1/status"},
		{http.MethodPost, "/management/v1/start"},
		{http.MethodPost, "/management/v1/login-ticket"},
		{http.MethodGet, "/login"},
		{http.MethodGet, "/gateways/primary/v1/api/tickle"},
		{http.MethodGet, "/v1/api/tickle"},
	} {
		request := httptest.NewRequest(route.method, route.path, nil)
		request.Header.Set("Authorization", "Bearer secret")
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		if response.Code != http.StatusNotFound {
			t.Fatalf("legacy route %s %s = %d: %s", route.method, route.path, response.Code, response.Body.String())
		}
	}
}

func TestLoginTicketRequiresDedicatedProxy(t *testing.T) {
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {}))
	defer upstream.Close()
	handler := newTestServer(t, &fakeGateway{baseURL: upstream.URL}, "secret")

	request := httptest.NewRequest(http.MethodPost, "/management/v1/gateways/primary/login-ticket", nil)
	request.Header.Set("Authorization", "Bearer secret")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusConflict {
		t.Fatalf("ticket without dedicated proxy = %d: %s", response.Code, response.Body.String())
	}
}

func TestMultipleGatewaysOperateIndependently(t *testing.T) {
	alphaUpstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("alpha:" + r.URL.Path))
	}))
	defer alphaUpstream.Close()
	betaUpstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("beta:" + r.URL.Path))
	}))
	defer betaUpstream.Close()

	alpha := &fakeGateway{baseURL: alphaUpstream.URL}
	beta := &fakeGateway{baseURL: betaUpstream.URL}
	cfg := multiTestConfig(t, alphaUpstream.URL, betaUpstream.URL, "secret")
	handler, err := newServer(map[string]Gateway{"alpha": alpha, "beta": beta}, nil, filepath.Join(t.TempDir(), "config.json"), cfg)
	if err != nil {
		t.Fatal(err)
	}

	operation := func(method, path string) {
		t.Helper()
		request := httptest.NewRequest(method, path, nil)
		request.Header.Set("Authorization", "Bearer secret")
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		if response.Code != http.StatusOK {
			t.Fatalf("%s = %d: %s", path, response.Code, response.Body.String())
		}
	}
	operation(http.MethodPost, "/management/v1/gateways/alpha/start")
	operation(http.MethodPost, "/management/v1/gateways/beta/start")
	operation(http.MethodPost, "/management/v1/gateways/alpha/stop")
	if alpha.started != 1 || alpha.stopped != 1 || beta.started != 1 || beta.stopped != 0 {
		t.Fatalf("lifecycle leaked: alpha=%+v beta=%+v", alpha, beta)
	}
}

func TestDedicatedProxyPreservesRootPathsAndSharesAuthentication(t *testing.T) {
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); got != "" {
			t.Errorf("proxy credential reached Gateway: %q", got)
		}
		http.SetCookie(w, &http.Cookie{Name: "JSESSIONID", Value: "upstream", Path: "/sso"})
		_, _ = w.Write([]byte(r.Method + ":" + r.URL.RequestURI()))
	}))
	defer upstream.Close()
	cfg := appconfig.Config{Username: "admin", Password: "test-password", SessionTTLMinutes: 30,
		ListenAddr: "127.0.0.1:8088", PublicURL: "http://manager.test", APIToken: "shared-key",
		Gateways: map[string]appconfig.GatewayInstance{
			"alpha": {
				Config:          gateway.Config{GatewayDir: t.TempDir(), GatewayPort: 5680, GatewayURL: upstream.URL},
				ProxyListenAddr: "127.0.0.1:18081", ProxyPublicURL: "http://alpha.test:18081",
				ProxyToken: "alpha-key",
			},
		},
	}
	handler, err := newServer(map[string]Gateway{"alpha": &fakeGateway{baseURL: upstream.URL}}, nil, filepath.Join(t.TempDir(), "config.json"), cfg)
	if err != nil {
		t.Fatal(err)
	}

	unauthorized := httptest.NewRecorder()
	handler.ServeGatewayProxy("alpha", unauthorized, httptest.NewRequest(http.MethodGet, "/sso/Login", nil))
	if unauthorized.Code != http.StatusUnauthorized || !strings.HasPrefix(unauthorized.Header().Get("WWW-Authenticate"), "Bearer") {
		t.Fatalf("unauthorized response = %d, %q", unauthorized.Code, unauthorized.Header().Get("WWW-Authenticate"))
	}

	for name, authorize := range map[string]func(*http.Request){
		"bearer": func(r *http.Request) { r.Header.Set("Authorization", "Bearer alpha-key") },
	} {
		t.Run(name, func(t *testing.T) {
			request := httptest.NewRequest(http.MethodPost, "/sso/Authenticator?paper=true", nil)
			authorize(request)
			response := httptest.NewRecorder()
			handler.ServeGatewayProxy("alpha", response, request)
			if response.Code != http.StatusOK || response.Body.String() != "POST:/sso/Authenticator?paper=true" {
				t.Fatalf("proxy response = %d %q", response.Code, response.Body.String())
			}
			cookies := response.Result().Cookies()
			if len(cookies) != 1 || cookies[0].Name != "JSESSIONID" || cookies[0].Path != "/sso" {
				t.Fatalf("transparent dedicated proxy cookies = %#v", cookies)
			}
		})
	}
}

func TestProxyTokensAreIsolatedPerGateway(t *testing.T) {
	alphaUpstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("alpha"))
	}))
	defer alphaUpstream.Close()
	betaUpstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("beta"))
	}))
	defer betaUpstream.Close()
	cfg := appconfig.Config{Username: "admin", Password: "test-password", SessionTTLMinutes: 30,
		ListenAddr: "127.0.0.1:8088", PublicURL: "http://manager.test", APIToken: "manager-key",
		Gateways: map[string]appconfig.GatewayInstance{
			"alpha": {
				Config:          gateway.Config{GatewayDir: filepath.Join(t.TempDir(), "alpha"), GatewayPort: 5680, GatewayURL: alphaUpstream.URL},
				ProxyListenAddr: "127.0.0.1:18081", ProxyPublicURL: "http://alpha.test:18081", ProxyToken: "alpha-key",
			},
			"beta": {
				Config:          gateway.Config{GatewayDir: filepath.Join(t.TempDir(), "beta"), GatewayPort: 5681, GatewayURL: betaUpstream.URL},
				ProxyListenAddr: "127.0.0.1:18082", ProxyPublicURL: "http://beta.test:18082", ProxyToken: "beta-key",
			},
		},
	}
	handler, err := newServer(map[string]Gateway{
		"alpha": &fakeGateway{baseURL: alphaUpstream.URL},
		"beta":  &fakeGateway{baseURL: betaUpstream.URL},
	}, nil, filepath.Join(t.TempDir(), "config.json"), cfg)
	if err != nil {
		t.Fatal(err)
	}

	for _, test := range []struct {
		id, token string
		want      int
	}{
		{id: "alpha", token: "alpha-key", want: http.StatusOK},
		{id: "alpha", token: "beta-key", want: http.StatusUnauthorized},
		{id: "beta", token: "beta-key", want: http.StatusOK},
		{id: "beta", token: "manager-key", want: http.StatusUnauthorized},
	} {
		request := httptest.NewRequest(http.MethodGet, "/v1/api/tickle", nil)
		request.Header.Set("Authorization", "Bearer "+test.token)
		response := httptest.NewRecorder()
		handler.ServeGatewayProxy(test.id, response, request)
		if response.Code != test.want {
			t.Fatalf("gateway %s with token %q = %d, want %d", test.id, test.token, response.Code, test.want)
		}
	}
}

func TestDedicatedProxyRewritesSSOOriginAndStartsWithFreshCookies(t *testing.T) {
	var gotOrigin, gotReferer string
	var gotCookies []*http.Cookie
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotOrigin = r.Header.Get("Origin")
		gotReferer = r.Header.Get("Referer")
		gotCookies = r.Cookies()
		http.SetCookie(w, &http.Cookie{Name: "JSESSIONID", Value: "fresh", Path: "/sso"})
		_, _ = w.Write([]byte("login"))
	}))
	defer upstream.Close()
	publicURL := "https://alpha.test:18081"
	cfg := appconfig.Config{Username: "admin", Password: "test-password", SessionTTLMinutes: 30,
		ListenAddr: "127.0.0.1:8088", PublicURL: "http://manager.test", APIToken: "shared-key",
		Gateways: map[string]appconfig.GatewayInstance{
			"alpha": {
				Config:          gateway.Config{GatewayDir: t.TempDir(), GatewayPort: 5680, GatewayURL: upstream.URL},
				ProxyListenAddr: "127.0.0.1:18081", ProxyPublicURL: publicURL,
				ProxyToken: "alpha-key",
			},
		},
	}
	handler, err := newServer(map[string]Gateway{"alpha": &fakeGateway{baseURL: upstream.URL}}, nil, filepath.Join(t.TempDir(), "config.json"), cfg)
	if err != nil {
		t.Fatal(err)
	}

	request := httptest.NewRequest(http.MethodGet, "/sso/Login?paper=true", nil)
	request.Header.Set("Authorization", "Bearer alpha-key")
	request.Header.Set("Origin", publicURL)
	request.Header.Set("Referer", publicURL+"/sso/Login?forwardTo=22")
	request.AddCookie(&http.Cookie{Name: "JSESSIONID", Value: "stale"})
	request.AddCookie(&http.Cookie{Name: "x-sess-uuid", Value: "stale"})
	response := httptest.NewRecorder()
	handler.ServeGatewayProxy("alpha", response, request)

	target, err := url.Parse(upstream.URL)
	if err != nil {
		t.Fatal(err)
	}
	if gotOrigin != upstream.URL {
		t.Fatalf("Origin = %q, want %q", gotOrigin, upstream.URL)
	}
	if gotReferer != upstream.URL+"/sso/Login?forwardTo=22" {
		t.Fatalf("Referer = %q, target host %q", gotReferer, target.Host)
	}
	if len(gotCookies) != 0 {
		t.Fatalf("stale dedicated cookies reached Gateway: %#v", gotCookies)
	}
	var fresh, expired bool
	for _, cookie := range response.Result().Cookies() {
		switch cookie.Name {
		case "JSESSIONID":
			fresh = cookie.Value == "fresh"
		case "x-sess-uuid":
			expired = cookie.MaxAge < 0
		}
	}
	if !fresh || !expired {
		t.Fatalf("fresh=%v expired=%v cookies=%#v", fresh, expired, response.Result().Cookies())
	}
}

func TestDedicatedLoginTicketUsesProxyOriginAndCreatesScopedSession(t *testing.T) {
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(r.URL.Path))
	}))
	defer upstream.Close()
	cfg := appconfig.Config{Username: "admin", Password: "test-password", SessionTTLMinutes: 30,
		ListenAddr: "127.0.0.1:8088", PublicURL: "http://manager.test", APIToken: "shared-key",
		Gateways: map[string]appconfig.GatewayInstance{
			"alpha": {
				Config:          gateway.Config{GatewayDir: t.TempDir(), GatewayPort: 5680, GatewayURL: upstream.URL},
				ProxyListenAddr: "127.0.0.1:18081", ProxyPublicURL: "http://alpha.test:18081",
				ProxyToken: "alpha-key",
			},
		},
	}
	handler, err := newServer(map[string]Gateway{"alpha": &fakeGateway{baseURL: upstream.URL}}, nil, filepath.Join(t.TempDir(), "config.json"), cfg)
	if err != nil {
		t.Fatal(err)
	}
	handler.now = func() time.Time { return time.Unix(100, 0) }

	statusRequest := httptest.NewRequest(http.MethodGet, "/management/v1/gateways/alpha/status", nil)
	statusRequest.Header.Set("Authorization", "Bearer shared-key")
	statusResponse := httptest.NewRecorder()
	handler.ServeHTTP(statusResponse, statusRequest)
	var status gateway.GatewayStatus
	if err := json.Unmarshal(statusResponse.Body.Bytes(), &status); err != nil {
		t.Fatal(err)
	}
	if status.LoginURL != "http://alpha.test:18081/sso/Login" {
		t.Fatalf("public login URL = %q", status.LoginURL)
	}

	ticketRequest := httptest.NewRequest(http.MethodPost, "/management/v1/gateways/alpha/login-ticket", nil)
	ticketRequest.Header.Set("Authorization", "Bearer shared-key")
	ticketResponse := httptest.NewRecorder()
	handler.ServeHTTP(ticketResponse, ticketRequest)
	var ticketBody struct {
		URL string `json:"url"`
	}
	if err := json.Unmarshal(ticketResponse.Body.Bytes(), &ticketBody); err != nil {
		t.Fatal(err)
	}
	loginURL, err := url.Parse(ticketBody.URL)
	if err != nil {
		t.Fatal(err)
	}
	if loginURL.Scheme != "http" || loginURL.Host != "alpha.test:18081" || loginURL.Path != dedicatedLoginPath {
		t.Fatalf("dedicated ticket URL = %q", ticketBody.URL)
	}

	loginRequest := httptest.NewRequest(http.MethodGet, loginURL.RequestURI(), nil)
	loginResponse := httptest.NewRecorder()
	handler.ServeGatewayProxy("alpha", loginResponse, loginRequest)
	if loginResponse.Code != http.StatusFound || loginResponse.Header().Get("Location") != "/sso/Login" {
		t.Fatalf("login exchange = %d, %q", loginResponse.Code, loginResponse.Header().Get("Location"))
	}
	cookies := loginResponse.Result().Cookies()
	if len(cookies) != 1 || cookies[0].Name != browserGatewaySessionCookie("alpha") || !cookies[0].HttpOnly {
		t.Fatalf("browser session cookies = %#v", cookies)
	}

	proxyRequest := httptest.NewRequest(http.MethodGet, "/sso/Login", nil)
	proxyRequest.AddCookie(cookies[0])
	proxyResponse := httptest.NewRecorder()
	handler.ServeGatewayProxy("alpha", proxyResponse, proxyRequest)
	if proxyResponse.Code != http.StatusOK || proxyResponse.Body.String() != "/sso/Login" {
		t.Fatalf("ticket session proxy = %d %q", proxyResponse.Code, proxyResponse.Body.String())
	}
}

func TestStartProxyListenersServesConfiguredInstance(t *testing.T) {
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("proxied:" + r.URL.Path))
	}))
	defer upstream.Close()
	probe, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	listenAddr := probe.Addr().String()
	_ = probe.Close()
	cfg := appconfig.Config{Username: "admin", Password: "test-password", SessionTTLMinutes: 30,
		ListenAddr: "127.0.0.1:8088", PublicURL: "http://manager.test", APIToken: "shared-key",
		Gateways: map[string]appconfig.GatewayInstance{
			"alpha": {
				Config:          gateway.Config{GatewayDir: t.TempDir(), GatewayPort: 5680, GatewayURL: upstream.URL},
				ProxyListenAddr: listenAddr, ProxyPublicURL: "http://" + listenAddr,
				ProxyToken: "alpha-key",
			},
		},
	}
	handler, err := newServer(map[string]Gateway{"alpha": &fakeGateway{baseURL: upstream.URL}}, nil, filepath.Join(t.TempDir(), "config.json"), cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := handler.StartProxyListeners(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = handler.ShutdownProxyListeners(ctx)
	})

	request, err := http.NewRequest(http.MethodGet, "http://"+listenAddr+"/v1/api/tickle", nil)
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Authorization", "Bearer alpha-key")
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	body, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != http.StatusOK || string(body) != "proxied:/v1/api/tickle" {
		t.Fatalf("listener response = %d %q", response.StatusCode, body)
	}
}

func TestSharedProxyListenerRoutesGatewaysByHostname(t *testing.T) {
	alphaUpstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("alpha:" + r.URL.Path))
	}))
	defer alphaUpstream.Close()
	betaUpstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("beta:" + r.URL.Path))
	}))
	defer betaUpstream.Close()

	certFile, keyFile := writeTestTLSKeyPair(t, alphaUpstream)
	sharedAddress := freeTCPAddress(t)
	_, sharedPort, err := net.SplitHostPort(sharedAddress)
	if err != nil {
		t.Fatal(err)
	}
	alphaAddress := freeTCPAddress(t)
	betaAddress := freeTCPAddress(t)
	baseDir := t.TempDir()
	cfg := appconfig.Config{Username: "admin", Password: "test-password", SessionTTLMinutes: 30,
		ListenAddr: "127.0.0.1:8088", PublicURL: "https://manager.localhost:" + sharedPort, APIToken: "secret",
		SharedProxyListenAddr: sharedAddress, ProxyTLSCertFile: certFile, ProxyTLSKeyFile: keyFile,
		Gateways: map[string]appconfig.GatewayInstance{
			"alpha": {
				Config:          gatewayConfigForUpstream(t, filepath.Join(baseDir, "alpha"), alphaUpstream.URL),
				ProxyListenAddr: alphaAddress, ProxyPublicURL: "https://alpha.localhost:" + sharedPort,
				ProxyToken: "alpha-key",
			},
			"beta": {
				Config:          gatewayConfigForUpstream(t, filepath.Join(baseDir, "beta"), betaUpstream.URL),
				ProxyListenAddr: betaAddress, ProxyPublicURL: "https://beta.localhost:" + sharedPort,
				ProxyToken: "beta-key",
			},
		},
	}
	if err := cfg.Validate(baseDir); err != nil {
		t.Fatal(err)
	}
	handler, err := newServer(map[string]Gateway{
		"alpha": &fakeGateway{baseURL: alphaUpstream.URL},
		"beta":  &fakeGateway{baseURL: betaUpstream.URL},
	}, nil, filepath.Join(baseDir, "config.json"), cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := handler.StartProxyListeners(); err != nil {
		t.Fatal(err)
	}
	for _, dedicatedAddress := range []string{alphaAddress, betaAddress} {
		if connection, err := net.DialTimeout("tcp", dedicatedAddress, 100*time.Millisecond); err == nil {
			_ = connection.Close()
			t.Fatalf("dedicated compatibility proxy %s is listening while the shared proxy is enabled", dedicatedAddress)
		}
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = handler.ShutdownProxyListeners(ctx)
	})

	client := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}}
	for id, instance := range handler.currentConfig().Gateways {
		if instance.ProxyPort != 0 || instance.ProxyListenAddr != "" || !handler.proxyIsListening(id) {
			t.Fatalf("shared proxy still depends on an instance listener: %#v", instance)
		}
	}
	// Browser login must work without a dedicated listener address, including
	// after a live configuration update has persisted the cleaned fields.
	putConfig(t, handler, handler.currentConfig())
	ticketRequest, err := http.NewRequest(http.MethodPost, "https://"+sharedAddress+"/management/v1/gateways/alpha/login-ticket", nil)
	if err != nil {
		t.Fatal(err)
	}
	ticketRequest.Host = "manager.localhost:" + sharedPort
	ticketRequest.Header.Set("Authorization", "Bearer secret")
	ticketResponse, err := client.Do(ticketRequest)
	if err != nil {
		t.Fatal(err)
	}
	var ticket struct {
		URL string `json:"url"`
	}
	decodeErr := json.NewDecoder(ticketResponse.Body).Decode(&ticket)
	_ = ticketResponse.Body.Close()
	if decodeErr != nil || ticketResponse.StatusCode != http.StatusCreated || !strings.HasPrefix(ticket.URL, "https://alpha.localhost:"+sharedPort+"/_manager/login?ticket=") {
		t.Fatalf("shared login ticket = %d %q (%v)", ticketResponse.StatusCode, ticket.URL, decodeErr)
	}
	ticketURL, err := url.Parse(ticket.URL)
	if err != nil {
		t.Fatal(err)
	}
	consumeRequest, err := http.NewRequest(http.MethodGet, "https://"+sharedAddress+ticketURL.RequestURI(), nil)
	if err != nil {
		t.Fatal(err)
	}
	consumeRequest.Host = ticketURL.Host
	loginClient := &http.Client{Transport: client.Transport, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	consumeResponse, err := loginClient.Do(consumeRequest)
	if err != nil {
		t.Fatal(err)
	}
	_ = consumeResponse.Body.Close()
	if consumeResponse.StatusCode != http.StatusFound || consumeResponse.Header.Get("Location") != "/sso/Login" || len(consumeResponse.Cookies()) == 0 || !consumeResponse.Cookies()[0].Secure {
		t.Fatalf("shared login ticket exchange = %d, cookies=%v", consumeResponse.StatusCode, consumeResponse.Cookies())
	}
	for _, test := range []struct {
		host, token, want string
	}{
		{"alpha.localhost:" + sharedPort, "alpha-key", "alpha:/v1/api/tickle"},
		{"beta.localhost:" + sharedPort, "beta-key", "beta:/v1/api/tickle"},
	} {
		request, err := http.NewRequest(http.MethodGet, "https://"+sharedAddress+"/v1/api/tickle", nil)
		if err != nil {
			t.Fatal(err)
		}
		request.Host = test.host
		request.Header.Set("Authorization", "Bearer "+test.token)
		response, err := client.Do(request)
		if err != nil {
			t.Fatal(err)
		}
		body, readErr := io.ReadAll(response.Body)
		_ = response.Body.Close()
		if readErr != nil {
			t.Fatal(readErr)
		}
		if response.StatusCode != http.StatusOK || string(body) != test.want {
			t.Fatalf("shared proxy %s = %d %q", test.host, response.StatusCode, body)
		}
	}

	managerRequest, err := http.NewRequest(http.MethodGet, "https://"+sharedAddress+"/manager/", nil)
	if err != nil {
		t.Fatal(err)
	}
	managerRequest.Host = "manager.localhost:" + sharedPort
	managerResponse, err := client.Do(managerRequest)
	if err != nil {
		t.Fatal(err)
	}
	managerBody, readErr := io.ReadAll(managerResponse.Body)
	_ = managerResponse.Body.Close()
	if readErr != nil {
		t.Fatal(readErr)
	}
	if managerResponse.StatusCode != http.StatusOK || !strings.Contains(string(managerBody), "IBKR Gateway Manager") {
		t.Fatalf("shared manager origin = %d %q", managerResponse.StatusCode, managerBody)
	}

	request, err := http.NewRequest(http.MethodGet, "https://"+sharedAddress+"/", nil)
	if err != nil {
		t.Fatal(err)
	}
	request.Host = "unknown.localhost:" + sharedPort
	response, err := client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	_ = response.Body.Close()
	if response.StatusCode != http.StatusMisdirectedRequest {
		t.Fatalf("unknown shared hostname = %d", response.StatusCode)
	}
}

func TestChangingSharedProxyModeRequiresRestart(t *testing.T) {
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("shared:" + r.URL.Path))
	}))
	defer upstream.Close()
	base := t.TempDir()
	dedicated := freeTCPAddress(t)
	cfg := appconfig.Config{Username: "admin", Password: "test-password", SessionTTLMinutes: 30,
		ListenAddr: "127.0.0.1:8088", PublicURL: "http://manager.localhost:8088", APIToken: "secret",
		Gateways: map[string]appconfig.GatewayInstance{
			"alpha": {Config: gatewayConfigForUpstream(t, filepath.Join(base, "alpha"), upstream.URL), ProxyListenAddr: dedicated, ProxyPublicURL: "http://" + dedicated, ProxyToken: "alpha-key"},
		},
	}
	if err := cfg.Validate(base); err != nil {
		t.Fatal(err)
	}
	handler, err := newServer(map[string]Gateway{"alpha": &fakeGateway{baseURL: upstream.URL}}, nil, filepath.Join(base, "config.json"), cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := handler.StartProxyListeners(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = handler.ShutdownProxyListeners(ctx)
	})
	connection, err := net.DialTimeout("tcp", dedicated, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	_ = connection.Close()
	shared := freeTCPAddress(t)
	cfg.SharedProxyListenAddr = shared
	cfg.ProxyTLSTerminated = true
	cfg.PublicURL = "https://manager.localhost"
	cfg.ProxyPublicURLTemplate = "https://{id}.localhost"
	instance := cfg.Gateways["alpha"]
	instance.ProxyPublicURL = "https://alpha.localhost"
	cfg.Gateways["alpha"] = instance
	data, err := json.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodPut, "/management/v1/config", strings.NewReader(string(data)))
	request.Header.Set("Authorization", "Bearer secret")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusBadGateway || !strings.Contains(response.Body.String(), "restarting the manager") {
		t.Fatalf("mode change = %d %s", response.Code, response.Body.String())
	}
	if handler.currentConfig().SharedProxyListenAddr != "" {
		t.Fatal("rejected mode change changed the active config")
	}
	connection, err = net.DialTimeout("tcp", dedicated, time.Second)
	if err != nil {
		t.Fatal("rejected mode change closed the existing listener:", err)
	}
	connection.Close()
}

func TestTLSTerminatedSharedProxyServesHTTPAndHostIndependentHealth(t *testing.T) {
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("primary:" + r.URL.Path))
	}))
	defer upstream.Close()

	sharedAddress := freeTCPAddress(t)
	baseDir := t.TempDir()
	cfg := appconfig.Config{Username: "admin", Password: "test-password", SessionTTLMinutes: 30,
		ListenAddr: sharedAddress, PublicURL: "https://manager.ibkr.example.com", APIToken: "manager-secret",
		SharedProxyListenAddr: sharedAddress, ProxyTLSTerminated: true,
		Gateways: map[string]appconfig.GatewayInstance{
			"primary": {
				Config:          gatewayConfigForUpstream(t, filepath.Join(baseDir, "primary"), upstream.URL),
				ProxyListenAddr: freeTCPAddress(t), ProxyPublicURL: "https://primary.ibkr.example.com",
				ProxyToken: "primary-secret",
			},
		},
	}
	if err := cfg.Validate(baseDir); err != nil {
		t.Fatal(err)
	}
	handler, err := newServer(map[string]Gateway{
		"primary": &fakeGateway{baseURL: upstream.URL},
	}, nil, filepath.Join(baseDir, "config.json"), cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := handler.StartProxyListeners(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = handler.ShutdownProxyListeners(ctx)
	})

	request, err := http.NewRequest(http.MethodGet, "http://"+sharedAddress+"/v1/api/tickle", nil)
	if err != nil {
		t.Fatal(err)
	}
	request.Host = "primary.ibkr.example.com"
	request.Header.Set("Authorization", "Bearer primary-secret")
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	body, readErr := io.ReadAll(response.Body)
	_ = response.Body.Close()
	if readErr != nil {
		t.Fatal(readErr)
	}
	if response.StatusCode != http.StatusOK || string(body) != "primary:/v1/api/tickle" {
		t.Fatalf("TLS-terminated proxy = %d %q", response.StatusCode, body)
	}

	healthRequest, err := http.NewRequest(http.MethodGet, "http://"+sharedAddress+"/healthz", nil)
	if err != nil {
		t.Fatal(err)
	}
	healthRequest.Host = "railway-healthcheck.invalid"
	healthResponse, err := http.DefaultClient.Do(healthRequest)
	if err != nil {
		t.Fatal(err)
	}
	defer healthResponse.Body.Close()
	if healthResponse.StatusCode != http.StatusOK {
		t.Fatalf("host-independent healthcheck = %d", healthResponse.StatusCode)
	}
}

func TestConfigUpdateMovesOnlyTheSelectedProxyListener(t *testing.T) {
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("alpha:" + r.URL.Path))
	}))
	defer upstream.Close()
	upstreamURL, err := url.Parse(upstream.URL)
	if err != nil {
		t.Fatal(err)
	}
	upstreamPort, err := net.LookupPort("tcp", upstreamURL.Port())
	if err != nil {
		t.Fatal(err)
	}
	freeAddress := func() string {
		t.Helper()
		listener, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		address := listener.Addr().String()
		_ = listener.Close()
		return address
	}
	firstAddress := freeAddress()
	secondAddress := freeAddress()
	baseDir := t.TempDir()
	cfg := appconfig.Config{Username: "admin", Password: "test-password", SessionTTLMinutes: 30,
		ListenAddr: "127.0.0.1:8088", PublicURL: "http://manager.test", APIToken: "secret",
		Gateways: map[string]appconfig.GatewayInstance{
			"alpha": {
				Config: gateway.Config{
					GatewayDir: filepath.Join(baseDir, "alpha"), GatewayPort: upstreamPort, GatewayURL: upstream.URL,
				},
				ProxyListenAddr: firstAddress, ProxyPublicURL: "http://" + firstAddress,
				ProxyToken: "alpha-key",
			},
		},
	}
	handler, err := newServer(map[string]Gateway{"alpha": &fakeGateway{baseURL: upstream.URL}}, nil, filepath.Join(baseDir, "config.json"), cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := handler.StartProxyListeners(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = handler.ShutdownProxyListeners(ctx)
	})

	updated := cfg
	instance := updated.Gateways["alpha"]
	instance.ProxyListenAddr = secondAddress
	instance.ProxyPublicURL = "http://" + secondAddress
	updated.Gateways = map[string]appconfig.GatewayInstance{"alpha": instance}
	putConfig(t, handler, updated)

	request, err := http.NewRequest(http.MethodGet, "http://"+secondAddress+"/sso/Login", nil)
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Authorization", "Bearer alpha-key")
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	body, err := io.ReadAll(response.Body)
	_ = response.Body.Close()
	if err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != http.StatusOK || string(body) != "alpha:/sso/Login" {
		t.Fatalf("moved proxy response = %d %q", response.StatusCode, body)
	}
	if _, err := net.DialTimeout("tcp", firstAddress, 100*time.Millisecond); err == nil {
		t.Fatal("old proxy listener is still accepting connections")
	}
}

func TestConfigReconcileAddsAndRemovesOnlyTargetInstances(t *testing.T) {
	baseDir := t.TempDir()
	alphaConfig := gateway.Config{
		GatewayDir: filepath.Join(baseDir, "alpha"), GatewayPort: 5680,
		GatewayURL: "https://127.0.0.1:5680",
	}
	betaConfig := gateway.Config{
		GatewayDir: filepath.Join(baseDir, "beta"), GatewayPort: 5681,
		GatewayURL: "https://127.0.0.1:5681",
	}
	cfg := appconfig.Config{Username: "admin", Password: "test-password", SessionTTLMinutes: 30,
		ListenAddr: "127.0.0.1:8088", PublicURL: "http://manager.test", APIToken: "secret",
		Gateways: map[string]appconfig.GatewayInstance{
			"alpha": {Config: alphaConfig},
		},
	}
	created := map[string]*fakeGateway{}
	factory := func(cfg gateway.Config) Gateway {
		manager := &fakeGateway{baseURL: cfg.GatewayURL}
		created[cfg.GatewayURL] = manager
		return manager
	}
	configPath := filepath.Join(baseDir, "config.json")
	handler, err := NewRegistry(configPath, cfg, factory)
	if err != nil {
		t.Fatal(err)
	}
	alpha := created[alphaConfig.GatewayURL]

	updated := cfg
	updated.Gateways = map[string]appconfig.GatewayInstance{
		"alpha": {Config: alphaConfig},
		"beta":  {Config: betaConfig, AutoStart: true},
	}
	putConfig(t, handler, updated)
	beta := created[betaConfig.GatewayURL]
	if beta == nil || beta.started != 1 || alpha.stopped != 0 {
		t.Fatalf("unexpected add lifecycle: alpha=%+v beta=%+v", alpha, beta)
	}

	updated.Gateways = map[string]appconfig.GatewayInstance{
		"beta": {Config: betaConfig, AutoStart: true},
	}
	putConfig(t, handler, updated)
	if alpha.stopped != 1 || beta.stopped != 0 {
		t.Fatalf("unexpected remove lifecycle: alpha=%+v beta=%+v", alpha, beta)
	}
}

func newTestServer(t *testing.T, manager Gateway, token string) *Server {
	t.Helper()
	cfg := appconfig.Config{Username: "admin", Password: "test-password", SessionTTLMinutes: 30,
		ListenAddr: "127.0.0.1:8088", PublicURL: "http://manager.test", APIToken: token,
		Gateways: map[string]appconfig.GatewayInstance{
			appconfig.DefaultGatewayID: {Config: gateway.Config{GatewayDir: t.TempDir(), GatewayPort: 5680, GatewayURL: manager.BaseURL()}},
		},
	}
	server, err := New(manager, t.TempDir()+"/config.json", cfg)
	if err != nil {
		t.Fatal(err)
	}
	return server
}

func multiTestConfig(t *testing.T, alphaURL, betaURL, token string) appconfig.Config {
	t.Helper()
	return appconfig.Config{Username: "admin", Password: "test-password", SessionTTLMinutes: 30,
		ListenAddr: "127.0.0.1:8088", PublicURL: "http://manager.test", APIToken: token,
		Gateways: map[string]appconfig.GatewayInstance{
			"alpha": {Config: gateway.Config{GatewayDir: filepath.Join(t.TempDir(), "alpha"), GatewayPort: 5680, GatewayURL: alphaURL}},
			"beta":  {Config: gateway.Config{GatewayDir: filepath.Join(t.TempDir(), "beta"), GatewayPort: 5681, GatewayURL: betaURL}},
		},
	}
}

func putConfig(t *testing.T, handler http.Handler, cfg appconfig.Config) {
	t.Helper()
	data, err := json.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodPut, "/management/v1/config", strings.NewReader(string(data)))
	request.Header.Set("Authorization", "Bearer secret")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("config update = %d: %s", response.Code, response.Body.String())
	}
}

func freeTCPAddress(t *testing.T) string {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := listener.Addr().String()
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}
	return address
}

func gatewayConfigForUpstream(t *testing.T, directory, rawURL string) gateway.Config {
	t.Helper()
	parsed, err := url.Parse(rawURL)
	if err != nil {
		t.Fatal(err)
	}
	port, err := strconv.Atoi(parsed.Port())
	if err != nil {
		t.Fatal(err)
	}
	return gateway.Config{GatewayDir: directory, GatewayPort: port, GatewayURL: rawURL}
}

func writeTestTLSKeyPair(t *testing.T, source *httptest.Server) (string, string) {
	t.Helper()
	certificate := source.TLS.Certificates[0]
	privateKey, err := x509.MarshalPKCS8PrivateKey(certificate.PrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	directory := t.TempDir()
	certFile := filepath.Join(directory, "proxy.crt")
	keyFile := filepath.Join(directory, "proxy.key")
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certificate.Certificate[0]})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privateKey})
	if err := os.WriteFile(certFile, certPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyFile, keyPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	return certFile, keyFile
}

func testDefaultConfig(base string) appconfig.Config {
	cfg := appconfig.Default(base)
	cfg.Username, cfg.Password, cfg.APIToken = "admin", "test-password", "secret"
	cfg.Gateways[appconfig.DefaultGatewayID] = appconfig.GatewayInstance{
		UseGlobalDefaults: true, AutoStart: true, ProxyPort: 18081,
		Config: gateway.Config{GatewayPort: 5680, GatewayLifecycle: "managed"},
	}
	return cfg
}
