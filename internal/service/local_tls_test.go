package service

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"io"
	"net"
	"net/http"
	"path/filepath"
	"testing"
	"time"

	"github.com/nite0x/ibkr-gateway-manager/gateway"
	"github.com/nite0x/ibkr-gateway-manager/internal/localtls"
)

func TestLocalTLSSharedListenerUsesGeneratedTrust(t *testing.T) {
	portListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := portListener.Addr().String()
	portListener.Close()
	dir := t.TempDir()
	cfg := testDefaultConfig(dir)
	cfg.Username = "admin"
	cfg.Password = "test-password"
	cfg.APIToken = "test-manager-token"
	cfg.LocalTLS = true
	cfg.ListenAddr = address
	cfg.PublicURL = ""
	handler, err := NewRegistry(filepath.Join(dir, "config.json"), cfg, func(c gateway.Config) Gateway { return &fakeGateway{baseURL: c.GatewayURL} })
	if err != nil {
		t.Fatal(err)
	}
	if err := handler.StartProxyListeners(); err != nil {
		t.Fatal(err)
	}
	defer handler.ShutdownProxyListeners(context.Background())
	_, ca, err := localtls.Inspect(filepath.Join(dir, "tls"))
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AppendCertsFromPEM(ca)
	transport := &http.Transport{TLSClientConfig: &tls.Config{RootCAs: roots}, DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, address)
	}}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 5 * time.Second}
	_, port, _ := net.SplitHostPort(address)
	for _, test := range []struct {
		host, path string
		status     int
	}{
		{"manager.localhost", "/manager/", 200},
		{"127.0.0.1", "/healthz", 200},
		{"primary.localhost", "/v1/api/tickle", 401},
		{"unknown.localhost", "/manager/", 421},
		{"manager.localhost", "/management/v1/local-tls", 401},
		{"manager.localhost", "/management/v1/local-tls/ca.crt", 401},
	} {
		response, err := client.Get("https://" + test.host + ":" + port + test.path)
		if err != nil {
			t.Fatal(err)
		}
		body, _ := io.ReadAll(response.Body)
		response.Body.Close()
		if response.StatusCode != test.status {
			t.Fatalf("%s%s: %d %s", test.host, test.path, response.StatusCode, body)
		}
	}
	for _, path := range []string{"/management/v1/local-tls", "/management/v1/local-tls/ca.crt"} {
		req, _ := http.NewRequest(http.MethodGet, "https://manager.localhost:"+port+path, nil)
		req.Header.Set("Authorization", "Bearer test-manager-token")
		response, err := client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		body, _ := io.ReadAll(response.Body)
		response.Body.Close()
		if response.StatusCode != http.StatusOK || bytes.Contains(body, []byte("PRIVATE KEY")) {
			t.Fatalf("certificate export: %d %s", response.StatusCode, body)
		}
		if path == "/management/v1/local-tls/ca.crt" {
			block, rest := pem.Decode(body)
			if block == nil || block.Type != "CERTIFICATE" || len(rest) != 0 {
				t.Fatal("export must contain exactly one public certificate")
			}
		}
	}
}
