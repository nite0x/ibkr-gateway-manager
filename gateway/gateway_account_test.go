package gateway

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestStatusResolvesRealAccount(t *testing.T) {
	for _, authSource := range []string{"tickle", "auth-status"} {
		t.Run(authSource, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch r.URL.Path {
				case "/v1/api/tickle":
					fmt.Fprintf(w, `{"userId":150630976,"iserver":{"authStatus":{"connected":true,"established":true,"authenticated":%t}}}`, authSource == "tickle")
				case "/v1/api/iserver/auth/status":
					fmt.Fprintf(w, `{"connected":true,"established":true,"authenticated":%t}`, authSource == "auth-status")
				case "/v1/api/sso/validate":
					fmt.Fprint(w, `{}`)
				case "/v1/api/portfolio/accounts":
					if r.Method != http.MethodGet {
						t.Errorf("account lookup method = %s, want GET", r.Method)
					}
					fmt.Fprint(w, `[{"id":"U15772871","accountId":"U15772871","parent":{"accountId":""}}]`)
				default:
					t.Errorf("unexpected request: %s", r.URL.Path)
					http.NotFound(w, r)
				}
			}))
			defer server.Close()
			manager := NewGatewayManager(Config{GatewayURL: server.URL, GatewayDir: t.TempDir()})
			manager.account = "U150630976"
			status := observedStatus(manager)
			if !status.Running || !status.Authenticated || status.Account != "U15772871" {
				t.Fatalf("unexpected status: %+v", status)
			}
		})
	}
}

func TestStatusAccountSelection(t *testing.T) {
	tests := []struct {
		name      string
		portfolio string
		code      int
		selected  string
		brokerage string
		want      string
	}{
		{name: "id only", portfolio: `[{"id":"DU12345"}]`, want: "DU12345"},
		{name: "accountId only", portfolio: `[{"accountId":"U12345"}]`, want: "U12345"},
		{name: "prefer accountId to display fields", portfolio: `[{"id":"alias","accountId":"U12345","displayName":"name"}]`, want: "U12345"},
		{name: "empty accounts", portfolio: `[]`},
		{name: "missing account ID", portfolio: `[{"displayName":"name"}]`},
		{name: "unauthorized", code: http.StatusUnauthorized, portfolio: `{"error":"unauthorized"}`},
		{name: "upstream error", code: http.StatusBadGateway, portfolio: `{"error":"unavailable"}`},
		{name: "invalid JSON", portfolio: `not JSON`},
		{name: "wrong shape", portfolio: `{"id":"U12345"}`},
		{name: "fresh explicit account fallback", code: http.StatusServiceUnavailable, selected: "DU12345", want: "DU12345"},
		{name: "portfolio overrides stale selection", portfolio: `[{"id":"U12345"}]`, selected: "U99999", want: "U12345"},
		{name: "multiple with tickle selection", portfolio: `[{"id":"U11111"},{"id":"U22222"}]`, selected: "U22222", want: "U22222"},
		{name: "multiple with brokerage selection", portfolio: `[{"id":"U11111"},{"id":"U22222"}]`, brokerage: "U22222", want: "U22222"},
		{name: "multiple without selection", portfolio: `[{"id":"U11111"},{"id":"U22222"}]`},
		{name: "selection outside portfolio", portfolio: `[{"id":"U11111"},{"id":"U22222"}]`, brokerage: "U99999"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch r.URL.Path {
				case "/v1/api/tickle":
					fmt.Fprintf(w, `{"connected":true,"established":true,"authenticated":true,"userId":150630976,"selectedAccount":%q}`, tt.selected)
				case "/v1/api/portfolio/accounts":
					if tt.code != 0 {
						w.WriteHeader(tt.code)
					}
					fmt.Fprint(w, tt.portfolio)
				case "/v1/api/iserver/accounts":
					fmt.Fprintf(w, `{"selectedAccount":%q}`, tt.brokerage)
				default:
					t.Errorf("unexpected request: %s", r.URL.Path)
					http.NotFound(w, r)
				}
			}))
			defer server.Close()
			manager := NewGatewayManager(Config{GatewayURL: server.URL, GatewayDir: t.TempDir()})
			manager.account = "U150630976"
			status := observedStatus(manager)
			if !status.Authenticated || status.Account != tt.want {
				t.Fatalf("authenticated=%t account=%q, want true %q", status.Authenticated, status.Account, tt.want)
			}
		})
	}
}

func TestStatusRefreshesAccountAcrossSessions(t *testing.T) {
	account := "U11111"
	authenticated := true
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/api/tickle", "/v1/api/iserver/auth/status":
			fmt.Fprintf(w, `{"connected":true,"established":true,"authenticated":%t,"userId":12345}`, authenticated)
		case "/v1/api/sso/validate":
			w.WriteHeader(http.StatusUnauthorized)
		case "/v1/api/portfolio/accounts":
			if !authenticated {
				t.Error("account lookup while unauthenticated")
			}
			fmt.Fprintf(w, `[{"id":%q}]`, account)
		default:
			http.NotFound(w, r)
		}
	}))
	manager := NewGatewayManager(Config{GatewayURL: server.URL, GatewayDir: t.TempDir()})
	defer server.Close()
	if got := observedStatus(manager).Account; got != account {
		t.Fatalf("first account = %q, want %q", got, account)
	}
	account = "DU22222"
	if got := observedStatus(manager).Account; got != account {
		t.Fatalf("switched account = %q, want %q", got, account)
	}
	authenticated = false
	if got := observedStatus(manager); got.Account != "" || got.Authenticated || got.SessionAgeSeconds != 0 {
		t.Fatalf("logged-out status retains session: %+v", got)
	}
	server.Close()
	if got := observedStatus(manager); got.Account != "" || got.SessionReady || !got.Stale {
		t.Fatalf("offline status retains session: %+v", got)
	}
}

func TestEnsureAuthenticatedDoesNotInventAccountFromUserID(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"connected":true,"established":true,"authenticated":true,"userId":150630976}`)
	}))
	defer server.Close()
	manager := NewGatewayManager(Config{GatewayURL: server.URL, GatewayDir: t.TempDir()})
	if err := manager.EnsureAuthenticated(context.Background()); err != nil {
		t.Fatal(err)
	}
	if manager.account != "" {
		t.Fatalf("invented account from userId: %q", manager.account)
	}
}

func observedStatus(g *GatewayManager) GatewayStatus {
	g.opMu.Lock()
	defer g.opMu.Unlock()
	g.refreshSession(context.Background(), false, false)
	return g.Status()
}
