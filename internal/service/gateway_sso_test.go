package service

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/nite0x/ibkr-gateway-manager/gateway"
	"github.com/nite0x/ibkr-gateway-manager/internal/appconfig"
)

func TestGatewaySSOScriptProxy(t *testing.T) {
	const vendorScript = `window.vendorLoaded = true;`
	for _, encoding := range []string{"identity", "gzip"} {
		t.Run(encoding, func(t *testing.T) {
			upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Header.Get("Accept-Encoding") != "identity" {
					t.Error("SSO bundle must request identity encoding")
				}
				for _, name := range []string{"If-None-Match", "If-Modified-Since", "Range", "If-Range"} {
					if r.Header.Get(name) != "" {
						t.Errorf("SSO bundle forwarded %s", name)
					}
				}
				body := []byte(vendorScript)
				if encoding == "gzip" {
					var compressed bytes.Buffer
					writer := gzip.NewWriter(&compressed)
					_, _ = writer.Write(body)
					_ = writer.Close()
					body = compressed.Bytes()
					w.Header().Set("Content-Encoding", "gzip")
				}
				w.Header().Set("Content-Type", "application/javascript; charset=utf-8")
				w.Header().Set("Content-Length", strconv.Itoa(len(body)))
				w.Header().Set("ETag", `"original"`)
				w.Header().Set("Last-Modified", "Mon, 07 Sep 2026 00:00:00 GMT")
				w.Header().Set("Content-Digest", "original")
				w.Header().Set("Cache-Control", "public, max-age=86400")
				_, _ = w.Write(body)
			}))
			defer upstream.Close()
			proxy, err := newGatewayProxy(upstream.URL, "https://primary.localhost:8081", nil)
			if err != nil {
				t.Fatal(err)
			}
			request := httptest.NewRequest(http.MethodGet, "https://primary.localhost:8081"+gatewaySSOBundlePath+"?v=1", nil)
			request.Header.Set("Accept-Encoding", "gzip, br")
			request.Header.Set("If-None-Match", `"original"`)
			request.Header.Set("If-Modified-Since", "Mon, 07 Sep 2026 00:00:00 GMT")
			request.Header.Set("Range", "bytes=0-10")
			request.Header.Set("If-Range", `"original"`)
			response := httptest.NewRecorder()
			proxy.ServeHTTP(response, request)
			if response.Code != http.StatusOK {
				t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
			}
			want := string(gatewayCookieScopeScript) + vendorScript
			if response.Body.String() != want {
				t.Fatal("cookie adapter must run before the unchanged vendor bundle")
			}
			if response.Header().Get("Content-Length") != strconv.Itoa(len(want)) || response.Header().Get("Cache-Control") != "no-store" {
				t.Fatal("incorrect transformed response metadata")
			}
			for _, name := range []string{"Content-Encoding", "ETag", "Last-Modified", "Content-Digest"} {
				if response.Header().Get(name) != "" {
					t.Errorf("stale %s on transformed bundle", name)
				}
			}
		})
	}
}

func TestLoginSuccessAutomaticallyInitializesBrokerage(t *testing.T) {
	var loggedIn, initialized atomic.Bool
	var inits atomic.Int32
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/sso/Dispatcher":
			loggedIn.Store(true)
			fmt.Fprint(w, "Client login succeeds")
		case "/v1/api/tickle", "/v1/api/iserver/auth/status":
			fmt.Fprintf(w, `{"authenticated":%t,"connected":true,"established":%t}`, initialized.Load(), initialized.Load())
		case "/v1/api/sso/validate":
			fmt.Fprintf(w, `{"RESULT":%t}`, loggedIn.Load())
		case "/v1/api/iserver/auth/ssodh/init":
			var payload map[string]bool
			if json.NewDecoder(r.Body).Decode(&payload) != nil || !payload["publish"] || !loggedIn.Load() {
				t.Error("login must validate SSO before initialization")
			}
			if !payload["compete"] {
				fmt.Fprint(w, `{"fail":"Force compete capability must be used together with compete flag"}`)
				return
			}
			inits.Add(1)
			initialized.Store(true)
			fmt.Fprint(w, `{}`)
		case "/v1/api/portfolio/accounts":
			fmt.Fprint(w, `[{"id":"DU123"}]`)
		default:
			t.Errorf("unexpected request %s", r.URL.Path)
			http.NotFound(w, r)
		}
	}))
	defer upstream.Close()
	g := gateway.NewGatewayManager(gateway.Config{GatewayURL: upstream.URL, GatewayDir: t.TempDir()})
	defer g.Shutdown()
	cfg := appconfig.Config{Username: "admin", Password: "test-password", SessionTTLMinutes: 30,
		Gateways: map[string]appconfig.GatewayInstance{"primary": {ProxyPublicURL: "https://primary.localhost:8088", ProxyToken: "instance-key"}},
	}
	s, err := newServer(map[string]Gateway{"primary": g}, nil, t.TempDir()+"/config.json", cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := g.ResumeSession(context.Background()); err != nil {
		t.Fatal(err)
	}
	// A request rejected by the Manager must not signal a successful login.
	unauth := httptest.NewRecorder()
	s.ServeGatewayProxy("primary", unauth, httptest.NewRequest("GET", "https://primary.localhost:8088/sso/Dispatcher", nil))
	if unauth.Code != http.StatusUnauthorized || loggedIn.Load() {
		t.Fatal("unauthenticated request reached the login observer")
	}
	req := httptest.NewRequest("GET", "https://primary.localhost:8088/sso/Dispatcher", nil)
	req.Header.Set("Authorization", "Bearer instance-key")
	response := httptest.NewRecorder()
	s.ServeGatewayProxy("primary", response, req)
	if response.Code != 200 || response.Body.String() != "Client login succeeds" {
		t.Fatalf("login page changed: %d %q", response.Code, response.Body.String())
	}
	deadline := time.Now().Add(2 * time.Second)
	for !g.Status().SessionReady && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if !g.Status().SessionReady || g.Status().Account != "DU123" || inits.Load() != 1 {
		t.Fatalf("proxy login did not become ready without manual init: %+v, inits=%d", g.Status(), inits.Load())
	}
}

func TestLoginObserverSignalsProgressWithoutChangingResponses(t *testing.T) {
	for _, tc := range []struct {
		name, path, body, encoding string
		status                     int
		want                       bool
	}{
		{"success", "/sso/Dispatcher", "Client login succeeds\n", "", 200, true},
		{"compressed success", "/sso/Dispatcher", "Client login succeeds", "gzip", 200, true},
		{"intermediate page", "/sso/Dispatcher", "<script>const text='Client login succeeds'</script>", "", 200, true},
		{"redirect", "/sso/Dispatcher", "Client login succeeds", "", 302, true},
		{"error", "/sso/Dispatcher", "Client login succeeds", "", 401, false},
		{"other endpoint", "/sso/Authenticator", "Client login succeeds", "", 200, false},
		{"oversized", "/sso/Dispatcher", strings.Repeat(" ", 65<<10) + "Client login succeeds", "", 200, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			body := []byte(tc.body)
			if tc.encoding == "gzip" {
				var compressed bytes.Buffer
				writer := gzip.NewWriter(&compressed)
				_, _ = writer.Write(body)
				_ = writer.Close()
				body = compressed.Bytes()
			}
			resp := &http.Response{StatusCode: tc.status, Request: httptest.NewRequest("POST", "https://primary.localhost"+tc.path, nil),
				Header: http.Header{"Content-Encoding": {tc.encoding}}, Body: io.NopCloser(bytes.NewReader(body))}
			called := false
			if err := observeGatewayLogin(resp, func() { called = true }); err != nil {
				t.Fatal(err)
			}
			got, err := io.ReadAll(resp.Body)
			_ = resp.Body.Close()
			if err != nil || !bytes.Equal(got, body) || called != tc.want {
				t.Fatalf("body changed or incorrect notification: called=%v err=%v", called, err)
			}
		})
	}
}

func TestGatewaySSOScriptLeavesOtherResponsesUnchanged(t *testing.T) {
	for _, tc := range []struct {
		name, method, path, contentType string
		status                          int
	}{
		{"API", "GET", "/v1/api/iserver/auth/status", "application/json", 200},
		{"other script", "GET", "/scripts/common.js", "application/javascript", 200},
		{"login HTML", "GET", gatewaySSOBundlePath, "text/html", 200},
		{"error", "GET", gatewaySSOBundlePath, "application/javascript", 403},
		{"head", "HEAD", gatewaySSOBundlePath, "application/javascript", 200},
	} {
		t.Run(tc.name, func(t *testing.T) {
			resp := &http.Response{
				StatusCode: tc.status,
				Request:    httptest.NewRequest(tc.method, "https://primary.localhost"+tc.path, nil),
				Header:     http.Header{"Content-Type": {tc.contentType}, "Etag": {`"original"`}},
				Body:       io.NopCloser(strings.NewReader("original")),
			}
			if err := rewriteGatewaySSOScript(resp); err != nil {
				t.Fatal(err)
			}
			body, _ := io.ReadAll(resp.Body)
			if string(body) != "original" || resp.Header.Get("ETag") != `"original"` {
				t.Fatal("unrelated response was changed")
			}
		})
	}
}

func TestGatewaySSOScriptRejectsInvalidRepresentations(t *testing.T) {
	for _, tc := range []struct{ name, encoding, body string }{
		{"broken gzip", "gzip", "not compressed"},
		{"unsupported encoding", "br", "compressed"},
		{"oversized", "", strings.Repeat("x", (8<<20)+1)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			resp := &http.Response{
				StatusCode: 200,
				Request:    httptest.NewRequest("GET", "https://primary.localhost"+gatewaySSOBundlePath, nil),
				Header:     http.Header{"Content-Type": {"text/javascript"}, "Content-Encoding": {tc.encoding}},
				Body:       io.NopCloser(strings.NewReader(tc.body)),
			}
			if err := rewriteGatewaySSOScript(resp); err == nil {
				t.Fatal("invalid script representation was accepted")
			}
		})
	}
}
