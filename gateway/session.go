package gateway

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// SessionSnapshot is the last observation, not a promise that an order will succeed.
// SessionGeneration changes whenever a trading session becomes ready again.
type SessionSnapshot struct {
	DesiredState      string `json:"desired_state"`
	ProcessOnline     bool   `json:"process_online"`
	SSOState          string `json:"sso_state"`
	SessionState      string `json:"session_state"`
	SessionReady      bool   `json:"session_ready"`
	SessionGeneration string `json:"session_generation,omitempty"`
	Connected         bool   `json:"connected"`
	Established       bool   `json:"established"`
	Competing         bool   `json:"competing"`
	LastCheckedAt     string `json:"last_checked_at,omitempty"`
	LastTickleAt      string `json:"last_tickle_at,omitempty"`
	NextRetryAt       string `json:"next_retry_at,omitempty"`
	RetryCount        int    `json:"retry_count"`
	SessionError      string `json:"session_error,omitempty"`
	Stale             bool   `json:"stale"`
}

const forceCompeteFailure = "Force compete capability must be used together with compete flag"

type brokerageAuth struct {
	Authenticated, Connected, Established, Competing bool
	Failure                                          string
}

func (a brokerageAuth) ready() bool {
	return a.Authenticated && a.Connected && a.Established && !a.Competing && a.Failure == ""
}
func decodeBrokerage(result map[string]interface{}) brokerageAuth {
	if iserver, ok := result["iserver"].(map[string]interface{}); ok {
		result, _ = iserver["authStatus"].(map[string]interface{})
	}
	a := brokerageAuth{}
	a.Authenticated, _ = result["authenticated"].(bool)
	a.Connected, _ = result["connected"].(bool)
	a.Established, _ = result["established"].(bool)
	a.Competing, _ = result["competing"].(bool)
	for _, key := range []string{"fail", "error"} {
		if value, ok := result[key].(string); ok && strings.TrimSpace(value) != "" {
			a.Failure = sanitizeAuditValue(value)
			if len(a.Failure) > 512 {
				a.Failure = a.Failure[:512] + "…"
			}
			break
		}
	}
	return a
}

// NotifyLoginComplete only accelerates polling. SSO validation and the explicit
// login action determine whether initialization is permitted; page text does not.
func (g *GatewayManager) NotifyLoginComplete() {
	g.mu.Lock()
	if g.session.DesiredState != desiredConnected {
		g.mu.Unlock()
		return
	}
	g.mu.Unlock()
	select {
	case g.wakeSession <- struct{}{}:
	default:
	}
}

type sessionHTTPError struct {
	Status int
	Path   string
}

func (e *sessionHTTPError) Error() string {
	return fmt.Sprintf("IBKR %s returned HTTP %d", e.Path, e.Status)
}
func unauthorized(err error) bool {
	var e *sessionHTTPError
	return errors.As(err, &e) && e.Status == http.StatusUnauthorized
}

// Do not log bodies: tickle and validate may contain session tokens and user data.
func (g *GatewayManager) sessionRequest(ctx context.Context, method, path string, body interface{}) (map[string]interface{}, error) {
	var reader io.Reader
	if method == http.MethodPost {
		if body == nil {
			body = map[string]interface{}{}
		}
		data, err := json.Marshal(body)
		if err != nil {
			return nil, err
		}
		reader = bytes.NewReader(data)
	}
	client, origin := g.httpEndpoint()
	req, err := http.NewRequestWithContext(ctx, method, origin+"/v1/api"+path, reader)
	if err != nil {
		return nil, err
	}
	if method == http.MethodPost {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if ctx.Err() == nil {
		g.mu.Lock()
		g.session.ProcessOnline = true
		g.mu.Unlock()
	}
	if resp.StatusCode != http.StatusOK {
		return nil, &sessionHTTPError{resp.StatusCode, path}
	}
	var result map[string]interface{}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&result); err != nil {
		return nil, fmt.Errorf("IBKR %s: invalid JSON response", path)
	}
	if result == nil {
		return nil, fmt.Errorf("IBKR %s: empty response", path)
	}
	return result, nil
}

func (g *GatewayManager) loadIntent() {
	dir := g.config.stateDir()
	if dir == "" {
		return
	}
	data, err := os.ReadFile(dir + ".session-intent.json")
	if os.IsNotExist(err) {
		return
	}
	var record struct {
		DesiredState string `json:"desired_state"`
	}
	if err == nil {
		err = json.Unmarshal(data, &record)
	}
	if err == nil && !validDesiredState(record.DesiredState) {
		err = fmt.Errorf("invalid desired_state")
	}
	if err != nil {
		g.intentError = fmt.Errorf("read session intent: %w", err)
		g.session.DesiredState = desiredStopped
		g.lastError = g.intentError.Error()
		return
	}
	g.session.DesiredState = record.DesiredState
	if record.DesiredState != desiredConnected {
		g.session.SessionState = record.DesiredState
	}
}

// Called under opMu. Keep intent outside the replaceable installation directory.
func (g *GatewayManager) setIntent(intent string) error {
	if !validDesiredState(intent) {
		return fmt.Errorf("invalid desired_state %q", intent)
	}
	g.mu.Lock()
	dir := g.config.stateDir()
	g.mu.Unlock()
	if dir != "" {
		path := dir + ".session-intent.json"
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			return err
		}
		data, _ := json.Marshal(map[string]string{"desired_state": intent})
		file, err := os.CreateTemp(filepath.Dir(path), ".session-intent-*")
		if err != nil {
			return err
		}
		name := file.Name()
		defer os.Remove(name)
		if _, err = file.Write(data); err == nil {
			err = file.Sync()
		}
		closeErr := file.Close()
		if err == nil {
			err = closeErr
		}
		if err == nil {
			err = os.Rename(name, path)
		}
		if err != nil {
			return fmt.Errorf("save session intent: %w", err)
		}
	}
	g.mu.Lock()
	g.session.DesiredState = intent
	if g.intentError != nil {
		g.lastError = ""
	}
	g.intentError = nil
	g.mu.Unlock()
	return nil
}

// AutoStartGateway honors persisted operator intent. Explicit StartGateway resumes.
func (g *GatewayManager) AutoStartGateway(ctx context.Context) error {
	g.opMu.Lock()
	defer g.opMu.Unlock()
	g.mu.Lock()
	intent, err := g.session.DesiredState, g.intentError
	g.mu.Unlock()
	if err != nil {
		return err
	}
	if intent != desiredConnected {
		return nil
	}
	return g.startLocked(ctx)
}

func (g *GatewayManager) clearSession(state string) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.invalidateSessionLocked(state)
	g.stateUpdatedAt = time.Now().UTC()
	g.session.NextRetryAt, g.session.SessionError = "", ""
	g.session.RetryCount = 0
	g.session.Stale = false
	if state == desiredStopped {
		g.session.ProcessOnline = false
	}
}

// observe is the only writer of observed session status. Operations and probes are
// serialized by opMu; cancellation prevents an old monitor publishing a new snapshot.
func (g *GatewayManager) observe(ctx context.Context, state, sso string, auth brokerageAuth, err error, tickled bool, account string) {
	if ctx.Err() != nil {
		return
	}
	now := time.Now().UTC()
	g.mu.Lock()
	previous := g.session.SessionState
	wasReady := g.session.SessionReady
	g.session.SessionState, g.session.SSOState = state, sso
	g.session.Connected, g.session.Established, g.session.Competing = auth.Connected, auth.Established, auth.Competing
	g.session.SessionReady = state == sessionReady
	g.session.LastCheckedAt = now.Format(time.RFC3339Nano)
	g.session.Stale = err != nil
	g.session.SessionError, g.session.NextRetryAt = "", ""
	if tickled {
		g.session.LastTickleAt = now.Format(time.RFC3339Nano)
	}
	if err != nil {
		g.session.SessionError = sanitizeAuditValue(err.Error())
	}
	if state == sessionReady {
		g.loginInit = loginInitialization{}
		if !wasReady {
			g.session.SessionGeneration = fmt.Sprintf("%d", now.UnixNano())
			g.authenticatedAt = now
		}
		g.account = account
		g.session.RetryCount = 0
	} else {
		g.account, g.authenticatedAt = "", time.Time{}
		if state == sessionRecovering || state == sessionUnknown || state == sessionInitializing {
			g.session.RetryCount++
			g.session.NextRetryAt = now.Add(sessionRetryDelay(g.session.RetryCount)).Format(time.RFC3339Nano)
		} else {
			g.session.RetryCount = 0
		}
		if g.loginInit.pending() {
			g.session.RetryCount = g.loginInit.attempts
			g.session.NextRetryAt = ""
			if g.loginInit.active(now) {
				next := g.loginInit.nextAttempt
				if !next.After(now) {
					next = now.Add(5 * time.Second)
				}
				g.session.NextRetryAt = next.Format(time.RFC3339Nano)
			}
		}
	}
	if state == sessionLoginRequired {
		g.state = gatewayStateAuthRequired
	} else if g.session.ProcessOnline {
		g.state = gatewayStateRunning
	}
	if previous != state {
		g.stateUpdatedAt = now
	}
	g.mu.Unlock()
	if previous != state {
		g.audit("gateway.session", state, "previous="+previous)
	}
}

func sessionRetryDelay(attempt int) time.Duration {
	delays := []time.Duration{5 * time.Second, 15 * time.Second, 30 * time.Second, time.Minute, 2 * time.Minute, 5 * time.Minute}
	if attempt < 1 {
		attempt = 1
	}
	if attempt > len(delays) {
		attempt = len(delays)
	}
	return delays[attempt-1]
}

// refreshSession requires opMu. A successful SSO validation never establishes trading readiness.
func (g *GatewayManager) refreshSession(ctx context.Context, recoverSession, compete bool) {
	g.mu.Lock()
	desired := g.session.DesiredState
	loginPending := g.loginInit.pending()
	g.mu.Unlock()
	if desired != desiredConnected || ctx.Err() != nil {
		return
	}
	tickle, err := g.sessionRequest(ctx, http.MethodPost, "/tickle", nil)
	tickled := err == nil
	if err != nil && !unauthorized(err) {
		g.noteProbeFailure(err)
		g.observe(ctx, sessionUnknown, sessionUnknown, brokerageAuth{}, err, false, "")
		return
	}
	g.mu.Lock()
	g.session.ProcessOnline = true
	g.localFailures = 0
	g.mu.Unlock()
	auth := decodeBrokerage(tickle)
	if !auth.ready() && !unauthorized(err) {
		status, statusErr := g.sessionRequest(ctx, http.MethodPost, "/iserver/auth/status", nil)
		if statusErr == nil {
			auth = decodeBrokerage(status)
		} else if !unauthorized(statusErr) {
			g.observe(ctx, sessionUnknown, sessionUnknown, auth, statusErr, tickled, "")
			return
		}
	}
	if auth.ready() {
		account := g.fetchPortfolioAccount(tickleAccount(tickle))
		g.observe(ctx, sessionReady, ssoValid, auth, nil, tickled, account)
		return
	}
	if auth.Competing && !compete && !loginPending {
		g.observe(ctx, sessionCompeting, sessionUnknown, auth, nil, tickled, "")
		return
	}
	sso, ssoErr := g.sessionRequest(ctx, http.MethodGet, "/sso/validate", nil)
	valid, hasResult := sso["RESULT"].(bool)
	if unauthorized(ssoErr) || (ssoErr == nil && hasResult && !valid) {
		g.observe(ctx, sessionLoginRequired, ssoExpired, auth, nil, tickled, "")
		return
	}
	if ssoErr != nil || !hasResult {
		if ssoErr == nil {
			ssoErr = fmt.Errorf("SSO validation missing boolean RESULT")
		}
		g.observe(ctx, sessionUnknown, sessionUnknown, auth, ssoErr, tickled, "")
		return
	}
	if !recoverSession {
		g.observe(ctx, sessionInitializing, ssoValid, auth, nil, tickled, "")
		return
	}
	// An authenticated session still loading accounts needs time, not another init.
	if auth.Authenticated && !auth.Competing && auth.Failure == "" {
		g.observe(ctx, sessionInitializing, ssoValid, auth, nil, tickled, "")
		return
	}
	if ctx.Err() != nil {
		return
	}
	g.mu.Lock()
	loginInit, wait, budgetErr := g.loginInit.attempt(time.Now())
	attempts := g.loginInit.attempts
	previousError := g.session.SessionError
	g.mu.Unlock()
	if budgetErr != nil {
		g.observe(ctx, sessionTakeoverRequired, ssoValid, auth, budgetErr, tickled, "")
		return
	}
	if wait {
		var pendingErr error
		if previousError != "" {
			pendingErr = errors.New(previousError)
		}
		g.observe(ctx, sessionInitializing, ssoValid, auth, pendingErr, tickled, "")
		return
	}
	compete = compete || loginInit
	if loginInit {
		g.audit("gateway.login_init", "requested", fmt.Sprintf("initialize brokerage after SSO validation; attempt=%d", attempts))
	}
	initialized, initErr := g.sessionRequest(ctx, http.MethodPost, "/iserver/auth/ssodh/init", map[string]bool{"publish": true, "compete": compete})
	if initErr != nil {
		if unauthorized(initErr) {
			g.observeBrokerageUnauthorized(ctx, auth, initErr, tickled)
		} else {
			g.observe(ctx, sessionRecovering, ssoValid, auth, initErr, tickled, "")
		}
		return
	}
	if failure := decodeBrokerage(initialized); failure.Failure != "" {
		g.observeInitializationFailure(ctx, failure, tickled)
		return
	}
	status, err := g.sessionRequest(ctx, http.MethodPost, "/iserver/auth/status", nil)
	auth = decodeBrokerage(status)
	if err == nil && auth.Failure != "" {
		g.observeInitializationFailure(ctx, auth, tickled)
		return
	}
	if unauthorized(err) {
		g.observeBrokerageUnauthorized(ctx, auth, err, tickled)
		return
	}
	state := sessionRecovering
	if auth.Competing {
		state = sessionCompeting
	} else if auth.ready() {
		state = sessionReady
	}
	account := ""
	if state == sessionReady {
		account = g.fetchPortfolioAccount(tickleAccount(status))
	}
	g.observe(ctx, state, ssoValid, auth, err, tickled, account)
}

func (g *GatewayManager) observeBrokerageUnauthorized(ctx context.Context, auth brokerageAuth, err error, tickled bool) {
	// A brokerage 401 does not prove the independent SSO session expired.
	check, checkErr := g.sessionRequest(ctx, http.MethodGet, "/sso/validate", nil)
	if valid, ok := check["RESULT"].(bool); unauthorized(checkErr) || (checkErr == nil && ok && !valid) {
		g.observe(ctx, sessionLoginRequired, ssoExpired, auth, err, tickled, "")
	} else if checkErr == nil && valid {
		g.observe(ctx, sessionRecovering, ssoValid, auth, err, tickled, "")
	} else {
		g.observe(ctx, sessionUnknown, sessionUnknown, auth, err, tickled, "")
	}
}

func (g *GatewayManager) observeInitializationFailure(ctx context.Context, auth brokerageAuth, tickled bool) {
	state := sessionRecovering
	g.mu.Lock()
	retryingLogin := g.loginInit.active(time.Now())
	g.mu.Unlock()
	if auth.Competing && !retryingLogin {
		state = sessionCompeting
	} else if !retryingLogin && strings.EqualFold(strings.TrimSpace(auth.Failure), forceCompeteFailure) {
		state = sessionTakeoverRequired
	}
	g.observe(ctx, state, ssoValid, auth, fmt.Errorf("IBKR brokerage initialization: %s", auth.Failure), tickled, "")
}

// Only local transport failure is evidence for process recovery. An IBKR HTTP 5xx,
// malformed body, or expired login is not evidence that Java should be restarted.
func (g *GatewayManager) noteProbeFailure(err error) {
	var op *net.OpError
	g.mu.Lock()
	defer g.mu.Unlock()
	if errors.As(err, &op) && op.Op == "dial" {
		g.localFailures++
		g.session.ProcessOnline = false
	} else {
		g.localFailures = 0
	}
}

func (g *GatewayManager) RecoverSession(ctx context.Context, compete bool) error {
	g.opMu.Lock()
	defer g.opMu.Unlock()
	if err := g.acquireProcessLock(); err != nil {
		return err
	}
	if err := g.setIntent(desiredConnected); err != nil {
		return err
	}
	g.mu.Lock()
	g.session.RetryCount = 0
	if compete {
		g.loginInit = newLoginInitialization(time.Now())
	}
	g.mu.Unlock()
	g.refreshSession(ctx, true, compete)
	g.ensureSessionMonitor()
	status := g.Status()
	if !status.SessionReady {
		if status.SessionError != "" {
			return errors.New(status.SessionError)
		}
		return fmt.Errorf("brokerage session: %s", status.SessionState)
	}
	return nil
}

// ResumeSession records an explicit login attempt. The supervisor waits for valid
// SSO, then may initialize with bounded takeover retries for this login only.
func (g *GatewayManager) ResumeSession(ctx context.Context) error {
	g.opMu.Lock()
	defer g.opMu.Unlock()
	if err := g.acquireProcessLock(); err != nil {
		return err
	}
	if err := g.setIntent(desiredConnected); err != nil {
		return err
	}
	g.clearSession(sessionLoginRequired)
	g.mu.Lock()
	g.loginInit = newLoginInitialization(time.Now())
	g.mu.Unlock()
	g.ensureSessionMonitor()
	select {
	case g.wakeSession <- struct{}{}:
	default:
	}
	return nil
}

func (g *GatewayManager) ensureSessionMonitor() {
	g.mu.Lock()
	if g.ctx == nil {
		g.ctx, g.cancel = context.WithCancel(context.Background())
	}
	ctx := g.ctx
	g.mu.Unlock()
	g.StartTickler(ctx)
}

func (g *GatewayManager) Logout(ctx context.Context) error {
	g.opMu.Lock()
	defer g.opMu.Unlock()
	if err := g.acquireProcessLock(); err != nil {
		return err
	}
	// Persist before the request: even a failed logout must never auto-initialize.
	if err := g.setIntent(desiredLoggedOut); err != nil {
		return err
	}
	g.clearSession(desiredLoggedOut)
	result, err := g.sessionRequest(ctx, http.MethodPost, "/logout", nil)
	if unauthorized(err) {
		err = nil
	} else if err == nil {
		if success, _ := result["status"].(bool); !success {
			err = fmt.Errorf("IBKR did not confirm logout")
		}
	}
	g.mu.Lock()
	g.session.SSOState = sessionUnknown
	if err == nil {
		g.httpClient = newGatewayHTTPClient(g.config.GatewayURL, 10*time.Second)
		g.session.SSOState = ssoExpired
	} else {
		g.session.SessionError = sanitizeAuditValue(err.Error())
	}
	g.session.Stale = err != nil
	g.mu.Unlock()
	g.audit("gateway.logout", "requested", "automatic session recovery disabled")
	return err
}
