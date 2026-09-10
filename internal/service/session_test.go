package service

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/nite0x/ibkr-gateway-manager/internal/appconfig"
)

type sessionTestGateway struct {
	fakeGateway
	recovered, resumed, loggedOut int
	compete                       bool
}

func (g *sessionTestGateway) RecoverSession(_ context.Context, compete bool) error {
	g.recovered++
	g.compete = compete
	return nil
}
func (g *sessionTestGateway) ResumeSession(context.Context) error { g.resumed++; return nil }
func (g *sessionTestGateway) Logout(context.Context) error        { g.loggedOut++; return nil }

func TestSessionActionsRequireManagerAuthAndRevokeOnlyTheirInstance(t *testing.T) {
	g := &sessionTestGateway{fakeGateway: fakeGateway{baseURL: "https://127.0.0.1:5680"}}
	s := newTestServer(t, g, "manager-key")
	id := appconfig.DefaultGatewayID
	s.sessions["a"] = browserSession{GatewayID: id, Expires: time.Now().Add(time.Hour)}
	s.sessions["b"] = browserSession{GatewayID: "other", Expires: time.Now().Add(time.Hour)}
	s.tickets["a"] = loginTicket{GatewayID: id, Expires: time.Now().Add(time.Hour)}
	s.tickets["b"] = loginTicket{GatewayID: "other", Expires: time.Now().Add(time.Hour)}
	for _, action := range []string{"recover", "takeover", "resume", "logout"} {
		path := "/management/v1/gateways/" + id + "/" + action
		unauth := httptest.NewRecorder()
		s.ServeHTTP(unauth, httptest.NewRequest(http.MethodPost, path, nil))
		if unauth.Code != http.StatusUnauthorized {
			t.Fatalf("%s unauthenticated = %d", action, unauth.Code)
		}
		get := httptest.NewRequest(http.MethodGet, path, nil)
		get.Header.Set("Authorization", "Bearer manager-key")
		response := httptest.NewRecorder()
		s.ServeHTTP(response, get)
		if response.Code != http.StatusNotFound {
			t.Fatalf("GET %s mutated session", action)
		}
		req := httptest.NewRequest(http.MethodPost, path, nil)
		req.Header.Set("Authorization", "Bearer manager-key")
		response = httptest.NewRecorder()
		s.ServeHTTP(response, req)
		if response.Code != http.StatusOK {
			t.Fatalf("%s = %d: %s", action, response.Code, response.Body.String())
		}
		if action == "recover" && g.compete {
			t.Fatal("recover unexpectedly competes")
		}
	}
	if g.recovered != 2 || !g.compete || g.resumed != 1 || g.loggedOut != 1 {
		t.Fatalf("wrong action dispatch: %+v", g)
	}
	if len(s.sessions) != 1 || s.sessions["b"].GatewayID != "other" || len(s.tickets) != 1 || s.tickets["b"].GatewayID != "other" {
		t.Fatal("logout did not isolate browser credentials")
	}
}

type autoStartTestGateway struct {
	fakeGateway
	autoStarted chan struct{}
}

func (g *autoStartTestGateway) AutoStartGateway(context.Context) error {
	close(g.autoStarted)
	return nil
}
func TestConfiguredStartUsesPersistedIntentAwareEntryPoint(t *testing.T) {
	g := &autoStartTestGateway{fakeGateway: fakeGateway{baseURL: "https://127.0.0.1:5680"}, autoStarted: make(chan struct{})}
	s := newTestServer(t, g, "manager-key")
	cfg := s.config.Gateways[appconfig.DefaultGatewayID]
	cfg.AutoStart = true
	s.config.Gateways[appconfig.DefaultGatewayID] = cfg
	s.StartConfigured(context.Background())
	select {
	case <-g.autoStarted:
	case <-time.After(time.Second):
		t.Fatal("autostart bypassed persisted intent")
	}
	if g.started != 0 {
		t.Fatal("explicit start used by automatic startup")
	}
}
