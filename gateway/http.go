package gateway

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

func (g *GatewayManager) isOnline() bool {
	_, online := g.fetchTickle()
	return online
}

func (g *GatewayManager) isAuthenticated() bool {
	tickle, online := g.fetchTickle()
	return online && tickleAuthenticated(tickle)
}

func (g *GatewayManager) isHealthy() bool {
	if !g.isOnline() {
		return false
	}
	// Authentication is user-driven and should not cause a healthy local Java
	// process to restart continuously while it is waiting for browser login.
	return true
}

func (g *GatewayManager) fetchTickle() (map[string]interface{}, bool) {
	client, gatewayURL := g.httpEndpoint()
	resp, err := client.Post(
		gatewayURL+"/v1/api/tickle",
		"application/json",
		strings.NewReader("{}"),
	)
	if err != nil {
		return nil, false
	}
	defer resp.Body.Close()

	var result map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		result = nil
	}

	switch resp.StatusCode {
	case http.StatusOK, http.StatusUnauthorized:
		return result, true
	default:
		return nil, false
	}
}

// fetchPortfolioAccount resolves an actual account ID for the current session.
// A tickle userId identifies the user and must never be turned into an account ID.
func (g *GatewayManager) fetchPortfolioAccount(selected string) string {
	client, gatewayURL := g.httpEndpoint()
	resp, err := client.Get(gatewayURL + "/v1/api/portfolio/accounts")
	if err != nil {
		return selected
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return selected
	}
	var accounts []struct {
		ID        string `json:"id"`
		AccountID string `json:"accountId"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&accounts); err != nil {
		return selected
	}
	ids := make(map[string]bool, len(accounts))
	for _, account := range accounts {
		id := account.AccountID
		if id == "" {
			id = account.ID
		}
		if id != "" {
			ids[id] = true
		}
	}
	if len(ids) == 1 {
		for id := range ids {
			return id
		}
	}
	if ids[selected] {
		return selected
	}
	if len(ids) > 1 {
		// Do not arbitrarily label the first of several accounts as selected.
		resp, err := client.Get(gatewayURL + "/v1/api/iserver/accounts")
		if err != nil {
			return ""
		}
		defer resp.Body.Close()
		var result struct {
			SelectedAccount string `json:"selectedAccount"`
		}
		if resp.StatusCode == http.StatusOK && json.NewDecoder(resp.Body).Decode(&result) == nil && ids[result.SelectedAccount] {
			return result.SelectedAccount
		}
	}
	return ""
}

func (g *GatewayManager) fetchSSOValidate() (ok bool, message string) {
	result, err := g.sessionRequest(context.Background(), http.MethodGet, "/sso/validate", nil)
	if err != nil {
		return false, err.Error()
	}
	ok, _ = result["RESULT"].(bool)
	return ok, ""
}

func (g *GatewayManager) waitUntilOnline(ctx context.Context) bool {
	deadline := time.Now().Add(startupTimeout)
	for time.Now().Before(deadline) {
		select {
		case <-ctx.Done():
			return false
		case <-time.After(time.Second):
		}
		if g.isOnline() {
			return true
		}
	}
	return false
}

func (g *GatewayManager) loginMode() string {
	return "manual"
}

func (g *GatewayManager) httpEndpoint() (*http.Client, string) {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.httpClient, g.config.GatewayURL
}

func newGatewayHTTPClient(gatewayURL string, timeout time.Duration) *http.Client {
	transport := &http.Transport{}
	if parsed, err := url.Parse(gatewayURL); err == nil && isLoopbackHost(parsed.Hostname()) {
		// IBKR ships a self-signed certificate for the local Gateway. Certificate
		// verification is relaxed only for a loopback destination.
		transport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true} //nolint:gosec
	}
	return &http.Client{Timeout: timeout, Transport: transport}
}

func isLoopbackHost(host string) bool {
	host = strings.TrimSpace(strings.ToLower(host))
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func tickleAuthenticated(result map[string]interface{}) bool {
	if v, ok := result["authenticated"].(bool); ok {
		return v
	}
	iserver, ok := result["iserver"].(map[string]interface{})
	if !ok {
		return false
	}
	authStatus, ok := iserver["authStatus"].(map[string]interface{})
	if !ok {
		return false
	}
	authenticated, _ := authStatus["authenticated"].(bool)
	return authenticated
}

func tickleAccount(result map[string]interface{}) string {
	if acct, ok := result["account"].(string); ok && acct != "" {
		return acct
	}
	if acct, ok := result["selectedAccount"].(string); ok && acct != "" {
		return acct
	}
	// userId is a login identity, not a brokerage account number.
	return ""
}
