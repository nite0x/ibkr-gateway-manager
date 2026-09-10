package gateway

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

const readyAuth = `{"authenticated":true,"connected":true,"established":true,"competing":false}`

func TestSessionRecoveryAndStrictReadiness(t *testing.T) {
	tests := []struct {
		name, sso, initial, after, initBody string
		initCode                            int
		want                                string
		inits                               int32
	}{
		{name: "SSO success does not prove trading", sso: `{"RESULT":true}`, initial: `{"connected":true}`, after: `{}`, want: "recovering", inits: 1},
		{name: "SSO false with HTTP 200", sso: `{"RESULT":false}`, initial: `{}`, want: "login_required"},
		{name: "SSO missing result", sso: `{}`, initial: `{}`, want: "unknown"},
		{name: "SSO malformed", sso: `not-json`, initial: `{}`, want: "unknown"},
		{name: "recover expired brokerage", sso: `{"RESULT":true}`, initial: `{"connected":true}`, after: readyAuth, want: "ready", inits: 1},
		{name: "competing session", initial: `{"competing":true}`, want: "competing"},
		{name: "authenticated still loading", sso: `{"RESULT":true}`, initial: `{"authenticated":true,"connected":true,"established":false}`, want: "initializing"},
		{name: "brokerage denied with valid SSO", sso: `{"RESULT":true}`, initial: `{}`, initCode: 401, want: "recovering", inits: 1},
		{name: "initialize temporarily unavailable", sso: `{"RESULT":true}`, initial: `{}`, initCode: 503, want: "recovering", inits: 1},
		{name: "init body rejects force compete", sso: `{"RESULT":true}`, initial: `{}`, initBody: `{"fail":"Force compete capability must be used together with compete flag"}`, want: "takeover_required", inits: 1},
		{name: "status rejects force compete", sso: `{"RESULT":true}`, initial: `{}`, after: `{"connected":true,"fail":"Force compete capability must be used together with compete flag"}`, want: "takeover_required", inits: 1},
		{name: "init error with HTTP 200", sso: `{"RESULT":true}`, initial: `{}`, initBody: `{"error":"initialization rejected"}`, want: "recovering", inits: 1},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var inits atomic.Int32
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch r.URL.Path {
				case "/v1/api/tickle":
					fmt.Fprint(w, tt.initial)
				case "/v1/api/iserver/auth/status":
					if r.Method != http.MethodPost {
						t.Errorf("status uses %s", r.Method)
					}
					if inits.Load() > 0 && tt.after != "" {
						fmt.Fprint(w, tt.after)
					} else {
						fmt.Fprint(w, tt.initial)
					}
				case "/v1/api/sso/validate":
					fmt.Fprint(w, tt.sso)
				case "/v1/api/iserver/auth/ssodh/init":
					var payload map[string]bool
					if r.Method != http.MethodPost || json.NewDecoder(r.Body).Decode(&payload) != nil || !payload["publish"] || payload["compete"] {
						t.Errorf("unsafe init request")
					}
					inits.Add(1)
					if tt.initCode != 0 {
						w.WriteHeader(tt.initCode)
					}
					if tt.initBody != "" {
						fmt.Fprint(w, tt.initBody)
					} else {
						fmt.Fprint(w, `{}`)
					}
				case "/v1/api/portfolio/accounts":
					fmt.Fprint(w, `[{"id":"DU123"}]`)
				default:
					t.Errorf("unexpected path %s", r.URL.Path)
					http.NotFound(w, r)
				}
			}))
			defer server.Close()
			g := NewGatewayManager(Config{GatewayURL: server.URL, GatewayDir: filepath.Join(t.TempDir(), "gateway")})
			g.opMu.Lock()
			g.refreshSession(context.Background(), true, false)
			g.opMu.Unlock()
			got := g.Status()
			if got.SessionState != tt.want || inits.Load() != tt.inits {
				t.Fatalf("status=%+v inits=%d", got, inits.Load())
			}
			if got.SessionReady != (tt.want == "ready") || got.Authenticated != got.SessionReady {
				t.Fatalf("false readiness: %+v", got)
			}
			if (tt.initBody != "" || tt.want == "takeover_required" || tt.initCode >= 400) && got.SessionError == "" {
				t.Fatalf("initialization failure hidden: %+v", got)
			}
			if tt.want == "ready" && (got.Account != "DU123" || got.SessionGeneration == "") {
				t.Fatalf("missing ready metadata: %+v", got)
			}
			if g.shouldRestartProcess(context.Background()) {
				t.Fatal("authentication failure requested process restart")
			}
		})
	}
}

func TestStatusDoesNotMakeUpstreamRequests(t *testing.T) {
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { requests.Add(1); fmt.Fprint(w, readyAuth) }))
	defer server.Close()
	g := NewGatewayManager(Config{GatewayURL: server.URL, GatewayDir: t.TempDir()})
	for i := 0; i < 20; i++ {
		g.Status()
	}
	if requests.Load() != 0 {
		t.Fatal("status performed network I/O")
	}
}

func TestLogoutSerializesWithInFlightRecoveryAndPersists(t *testing.T) {
	initStarted, release := make(chan struct{}), make(chan struct{})
	var inits, logouts, ticks atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/api/tickle":
			ticks.Add(1)
			fmt.Fprint(w, `{"connected":true}`)
		case "/v1/api/iserver/auth/status":
			if inits.Load() > 0 {
				fmt.Fprint(w, readyAuth)
			} else {
				fmt.Fprint(w, `{"connected":true}`)
			}
		case "/v1/api/sso/validate":
			fmt.Fprint(w, `{"RESULT":true}`)
		case "/v1/api/iserver/auth/ssodh/init":
			inits.Add(1)
			close(initStarted)
			<-release
			fmt.Fprint(w, readyAuth)
		case "/v1/api/portfolio/accounts":
			fmt.Fprint(w, `[]`)
		case "/v1/api/logout":
			logouts.Add(1)
			fmt.Fprint(w, `{"status":true}`)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	cfg := Config{GatewayURL: server.URL, GatewayDir: filepath.Join(t.TempDir(), "instance")}
	g := NewGatewayManager(cfg)
	recoveryDone := make(chan struct{})
	go func() {
		g.opMu.Lock()
		g.refreshSession(context.Background(), true, false)
		g.opMu.Unlock()
		close(recoveryDone)
	}()
	<-initStarted
	logoutDone := make(chan error, 1)
	go func() { logoutDone <- g.Logout(context.Background()) }()
	close(release)
	<-recoveryDone
	if err := <-logoutDone; err != nil {
		t.Fatal(err)
	}
	before := ticks.Load()
	observedStatus(g)
	if inits.Load() != 1 || logouts.Load() != 1 || ticks.Load() != before {
		t.Fatal("logout resumed background requests")
	}
	if got := g.Status(); got.DesiredState != "logged_out" || got.SessionReady || got.Account != "" {
		t.Fatalf("logout snapshot: %+v", got)
	}
	restored := NewGatewayManager(cfg)
	if err := restored.AutoStartGateway(context.Background()); err != nil {
		t.Fatal(err)
	}
	if restored.Status().DesiredState != "logged_out" || ticks.Load() != before {
		t.Fatal("daemon restart ignored logout")
	}
	info, err := os.Stat(cfg.GatewayDir + ".session-intent.json")
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("intent permissions: %o", info.Mode().Perm())
	}
}

func TestFailedLogoutStillDisablesRecovery(t *testing.T) {
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { requests.Add(1); w.WriteHeader(503) }))
	defer server.Close()
	g := NewGatewayManager(Config{GatewayURL: server.URL, GatewayDir: t.TempDir()})
	if err := g.Logout(context.Background()); err == nil {
		t.Fatal("logout failure hidden")
	}
	observedStatus(g)
	if requests.Load() != 1 || g.Status().DesiredState != "logged_out" || !g.Status().Stale {
		t.Fatal("failed logout reactivated session")
	}
}

func TestStopAndShutdownHaveDifferentPersistedIntent(t *testing.T) {
	cfg := Config{GatewayDir: filepath.Join(t.TempDir(), "instance"), GatewayLifecycle: LifecyclePersistent}
	g := NewGatewayManager(cfg)
	if err := g.StopGateway(true); err != nil {
		t.Fatal(err)
	}
	restored := NewGatewayManager(cfg)
	if err := restored.AutoStartGateway(context.Background()); err != nil {
		t.Fatal(err)
	}
	if restored.Status().DesiredState != "stopped" {
		t.Fatal("explicit stop forgotten")
	}
	g.opMu.Lock()
	err := g.setIntent("connected")
	g.opMu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	if err := g.Shutdown(); err != nil {
		t.Fatal(err)
	}
	if NewGatewayManager(cfg).Status().DesiredState != "connected" {
		t.Fatal("daemon shutdown overwrote operator intent")
	}
}

func TestIntentIsPerInstanceAndCorruptionBlocksAutostart(t *testing.T) {
	dir := t.TempDir()
	a := Config{GatewayDir: filepath.Join(dir, "a")}
	b := Config{GatewayDir: filepath.Join(dir, "b")}
	first := NewGatewayManager(a)
	if err := first.StopGateway(true); err != nil {
		t.Fatal(err)
	}
	if NewGatewayManager(b).Status().DesiredState != "connected" {
		t.Fatal("another instance stopped")
	}
	if err := os.WriteFile(b.GatewayDir+".session-intent.json", []byte("broken"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := NewGatewayManager(b).AutoStartGateway(context.Background()); err == nil {
		t.Fatal("corrupt intent silently ignored")
	}
}

func TestSessionGenerationChangesOnRecovery(t *testing.T) {
	g := NewGatewayManager(Config{GatewayDir: t.TempDir()})
	ctx := context.Background()
	auth := decodeBrokerage(map[string]interface{}{"authenticated": true, "connected": true, "established": true})
	g.observe(ctx, "ready", "valid", auth, nil, true, "U1")
	first := g.Status().SessionGeneration
	g.observe(ctx, "ready", "valid", auth, nil, true, "U1")
	if g.Status().SessionGeneration != first {
		t.Fatal("healthy heartbeat changed generation")
	}
	g.observe(ctx, "unknown", "unknown", brokerageAuth{}, fmt.Errorf("temporary failure"), false, "")
	g.observe(ctx, "ready", "valid", auth, nil, true, "U1")
	if g.Status().SessionGeneration == first {
		t.Fatal("recovery did not invalidate old subscriptions")
	}
}

func TestProbeErrorsAndRestartBudget(t *testing.T) {
	g := NewGatewayManager(Config{GatewayDir: t.TempDir()})
	for i := 0; i < 10; i++ {
		g.noteProbeFailure(&sessionHTTPError{503, "/tickle"})
	}
	if g.shouldRestartProcess(context.Background()) {
		t.Fatal("503 must not restart Java")
	}
	dial := &net.OpError{Op: "dial", Err: fmt.Errorf("connection refused")}
	for cycle := 0; cycle < 4; cycle++ {
		for i := 0; i < 3; i++ {
			g.noteProbeFailure(dial)
		}
		if got := g.shouldRestartProcess(context.Background()); got != (cycle < 3) {
			t.Fatalf("restart budget cycle=%d allowed=%t", cycle, got)
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if g.shouldRestartProcess(ctx) {
		t.Fatal("canceled monitor allowed restart")
	}
	g.opMu.Lock()
	err := g.setIntent("stopped")
	g.opMu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	if g.shouldRestartProcess(context.Background()) {
		t.Fatal("stopped instance restarted")
	}
}

func TestCanceledProbeCannotPublishReady(t *testing.T) {
	entered := make(chan struct{})
	releaseHandler := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		close(entered)
		select {
		case <-r.Context().Done():
		case <-releaseHandler:
		}
	}))
	defer server.Close()
	defer close(releaseHandler)
	g := NewGatewayManager(Config{GatewayURL: server.URL, GatewayDir: t.TempDir()})
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { g.opMu.Lock(); g.refreshSession(ctx, true, false); g.opMu.Unlock(); close(done) }()
	<-entered
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("request ignored cancellation")
	}
	if g.Status().LastCheckedAt != "" || g.Status().SessionReady {
		t.Fatal("canceled observation published")
	}
}

func TestExplicitTakeoverOnly(t *testing.T) {
	var taken atomic.Bool
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/api/tickle":
			fmt.Fprint(w, `{"competing":true}`)
		case "/v1/api/iserver/auth/status":
			if taken.Load() {
				fmt.Fprint(w, readyAuth)
			} else {
				fmt.Fprint(w, `{"competing":true}`)
			}
		case "/v1/api/sso/validate":
			fmt.Fprint(w, `{"RESULT":true}`)
		case "/v1/api/iserver/auth/ssodh/init":
			var p map[string]bool
			_ = json.NewDecoder(r.Body).Decode(&p)
			taken.Store(p["compete"])
			fmt.Fprint(w, `{}`)
		case "/v1/api/portfolio/accounts":
			fmt.Fprint(w, `[]`)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	g := NewGatewayManager(Config{GatewayURL: server.URL, GatewayDir: t.TempDir()})
	g.opMu.Lock()
	g.refreshSession(context.Background(), true, false)
	g.opMu.Unlock()
	if taken.Load() {
		t.Fatal("automatic takeover")
	}
	g.opMu.Lock()
	g.refreshSession(context.Background(), true, true)
	g.opMu.Unlock()
	if !taken.Load() || !g.Status().SessionReady {
		t.Fatal("explicit takeover failed")
	}
}

func TestSessionRequestDoesNotExposeSecretBodies(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(503)
		fmt.Fprint(w, `{"session":"secret-value"}`)
	}))
	defer server.Close()
	g := NewGatewayManager(Config{GatewayURL: server.URL, GatewayDir: t.TempDir()})
	observedStatus(g)
	if strings.Contains(g.Status().SessionError, "secret-value") {
		t.Fatal("session secret exposed")
	}
	if !g.Status().ProcessOnline || !g.Status().Stale {
		t.Fatal("HTTP error confused process availability and session health")
	}
}

func TestSupervisorRunsWithoutStatusPollingAndStops(t *testing.T) {
	var ticks atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/api/tickle" {
			ticks.Add(1)
			fmt.Fprint(w, readyAuth)
		} else {
			fmt.Fprint(w, `[]`)
		}
	}))
	defer server.Close()
	g := NewGatewayManager(Config{GatewayURL: server.URL, GatewayDir: t.TempDir()})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	g.opMu.Lock()
	g.StartTickler(ctx)
	g.StartHealthMonitor(ctx)
	g.opMu.Unlock()
	g.wakeSession <- struct{}{}
	deadline := time.Now().Add(time.Second)
	for !g.Status().SessionReady && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if !g.Status().SessionReady || ticks.Load() != 1 {
		t.Fatalf("background supervisor did not update snapshot: %+v", g.Status())
	}
	g.mu.Lock()
	generation := g.monitorGeneration
	g.mu.Unlock()
	if generation != 1 {
		t.Fatal("duplicate supervisors started")
	}
	cancel()
	deadline = time.Now().Add(time.Second)
	for g.Status().SessionReady && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if g.Status().SessionReady || !g.Status().Stale {
		t.Fatal("canceled supervisor left a ready snapshot")
	}
	if ticks.Load() != 1 {
		t.Fatal("duplicate heartbeat")
	}
}

func TestSessionControlsRespectInstanceOwnership(t *testing.T) {
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { requests.Add(1); fmt.Fprint(w, readyAuth) }))
	defer server.Close()
	cfg := Config{GatewayURL: server.URL, GatewayDir: filepath.Join(t.TempDir(), "instance")}
	first, second := NewGatewayManager(cfg), NewGatewayManager(cfg)
	if err := first.acquireProcessLock(); err != nil {
		t.Fatal(err)
	}
	defer first.releaseProcessLock()
	for _, op := range []func() error{
		func() error { return second.RecoverSession(context.Background(), false) },
		func() error { return second.ResumeSession(context.Background()) },
		func() error { return second.Logout(context.Background()) },
		func() error { return second.StartGateway(context.Background()) },
		func() error { return second.StopGateway(true) },
	} {
		if err := op(); err == nil {
			t.Fatal("second controller bypassed instance ownership")
		}
	}
	if requests.Load() != 0 {
		t.Fatal("unowned instance received session requests")
	}
}

func TestLoginPollingSlowsDownAndRetryDelayIsBounded(t *testing.T) {
	g := NewGatewayManager(Config{GatewayDir: t.TempDir()})
	g.clearSession("login_required")
	if got := g.nextSessionDelay(); got != 5*time.Second {
		t.Fatalf("active login delay=%v", got)
	}
	g.mu.Lock()
	g.stateUpdatedAt = time.Now().Add(-11 * time.Minute)
	g.mu.Unlock()
	if got := g.nextSessionDelay(); got != time.Minute {
		t.Fatalf("idle login delay=%v", got)
	}
	if got := sessionRetryDelay(999); got != 5*time.Minute {
		t.Fatalf("unbounded retries=%v", got)
	}
}

func TestLoginInitializationRetriesWithoutSuccessPage(t *testing.T) {
	var valid, ready atomic.Bool
	var attempts []bool
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/api/tickle", "/v1/api/iserver/auth/status":
			if ready.Load() {
				fmt.Fprint(w, readyAuth)
			} else {
				fmt.Fprint(w, `{"connected":true}`)
			}
		case "/v1/api/sso/validate":
			fmt.Fprintf(w, `{"RESULT":%t}`, valid.Load())
		case "/v1/api/iserver/auth/ssodh/init":
			var payload map[string]bool
			_ = json.NewDecoder(r.Body).Decode(&payload)
			attempts = append(attempts, payload["compete"])
			if len(attempts) == 1 {
				w.WriteHeader(503)
				return
			}
			if len(attempts) == 2 {
				fmt.Fprint(w, `{"fail":"Force compete capability must be used together with compete flag"}`)
				return
			}
			ready.Store(true)
			fmt.Fprint(w, `{}`)
		case "/v1/api/portfolio/accounts":
			fmt.Fprint(w, `[{"id":"DU123"}]`)
		default:
			t.Errorf("unexpected path %s", r.URL.Path)
		}
	}))
	defer server.Close()
	g := NewGatewayManager(Config{GatewayURL: server.URL, GatewayDir: t.TempDir()})
	g.opMu.Lock()
	defer g.opMu.Unlock()
	// Same scope as ResumeSession, without starting a concurrent monitor in this test.
	g.loginInit = newLoginInitialization(time.Now())
	g.refreshSession(context.Background(), true, false)
	if len(attempts) != 0 || g.Status().SSOState != "expired" {
		t.Fatal("init bypassed SSO validation")
	}
	valid.Store(true)
	// No NotifyLoginComplete: server-side SSO detection must be sufficient.
	for i := 1; i <= 3; i++ {
		g.mu.Lock()
		g.loginInit.nextAttempt = time.Time{}
		g.mu.Unlock()
		g.refreshSession(context.Background(), true, false)
		if len(attempts) != i || !attempts[i-1] {
			t.Fatalf("retry lost takeover permission: %v", attempts)
		}
		if i < 3 {
			if g.Status().SessionError == "" || g.Status().SessionReady {
				t.Fatalf("failure hidden: %+v", g.Status())
			}
			deadline := g.loginInit.deadline
			g.NotifyLoginComplete()
			if g.loginInit.deadline != deadline {
				t.Fatal("notification renewed retry budget")
			}
			g.refreshSession(context.Background(), true, false)
			if len(attempts) != i {
				t.Fatal("notification bypassed retry backoff")
			}
		}
	}
	if !g.Status().SessionReady || g.loginInit.pending() {
		t.Fatal("successful initialization did not clear permission")
	}
	// A later lost brokerage session is ordinary recovery, not a new login.
	ready.Store(false)
	g.refreshSession(context.Background(), true, false)
	if len(attempts) != 4 || attempts[3] {
		t.Fatalf("ordinary recovery competes: %v", attempts)
	}
}

func TestLoginInitializationBudget(t *testing.T) {
	now := time.Now()
	l := newLoginInitialization(now)
	// Time spent at MFA must not consume the two-minute initialization budget.
	now = now.Add(9 * time.Minute)
	for i := 1; i <= loginInitializationMaxAttempts; i++ {
		compete, wait, err := l.attempt(now)
		if !compete || wait || err != nil || l.attempts != i {
			t.Fatalf("attempt %d: %+v %v", i, l, err)
		}
		now = l.nextAttempt
	}
	if _, _, err := l.attempt(now); err == nil || !l.exhausted {
		t.Fatal("retry limit ignored")
	}
	l = newLoginInitialization(now)
	if _, _, err := l.attempt(now.Add(11 * time.Minute)); err == nil {
		t.Fatal("expired login permission used")
	}
	l = newLoginInitialization(now)
	_, _, _ = l.attempt(now)
	if _, _, err := l.attempt(now.Add(2 * time.Minute)); err == nil {
		t.Fatal("initialization deadline ignored")
	}
}

func TestLoginNotificationCannotGrantOrRenewPermission(t *testing.T) {
	g := NewGatewayManager(Config{GatewayDir: t.TempDir()})
	g.NotifyLoginComplete()
	if g.loginInit.pending() {
		t.Fatal("page alone authorized takeover")
	}
	for _, state := range []string{desiredStopped, desiredLoggedOut} {
		g.loginInit = newLoginInitialization(time.Now())
		if err := g.setIntent(state); err != nil {
			t.Fatal(err)
		}
		g.clearSession(state)
		g.NotifyLoginComplete()
		if g.loginInit.pending() {
			t.Fatal("late notification re-enabled stopped instance")
		}
	}
	g.loginInit = newLoginInitialization(time.Now().Add(-11 * time.Minute))
	before := g.loginInit
	g.NotifyLoginComplete()
	if g.loginInit != before {
		t.Fatal("notification renewed expired permission")
	}
	// A different instance cannot inherit this one's permission.
	other := NewGatewayManager(Config{GatewayDir: t.TempDir()})
	if other.loginInit.pending() {
		t.Fatal("cross-instance permission leak")
	}
}

func TestSupervisorDetectsSSOWithoutBrowserNotification(t *testing.T) {
	var valid, initialized atomic.Bool
	checked := make(chan struct{}, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/api/tickle", "/v1/api/iserver/auth/status":
			if initialized.Load() {
				fmt.Fprint(w, readyAuth)
			} else {
				fmt.Fprint(w, `{"connected":true}`)
			}
		case "/v1/api/sso/validate":
			fmt.Fprintf(w, `{"RESULT":%t}`, valid.Load())
			select {
			case checked <- struct{}{}:
			default:
			}
		case "/v1/api/iserver/auth/ssodh/init":
			var payload map[string]bool
			_ = json.NewDecoder(r.Body).Decode(&payload)
			if !valid.Load() || !payload["publish"] || !payload["compete"] {
				t.Error("invalid automatic initialization")
			}
			initialized.Store(true)
			fmt.Fprint(w, `{}`)
		case "/v1/api/portfolio/accounts":
			fmt.Fprint(w, `[]`)
		default:
			t.Errorf("unexpected path %s", r.URL.Path)
		}
	}))
	defer server.Close()
	g := NewGatewayManager(Config{GatewayURL: server.URL, GatewayDir: t.TempDir()})
	defer g.Shutdown()
	if err := g.ResumeSession(context.Background()); err != nil {
		t.Fatal(err)
	}
	select {
	case <-checked:
	case <-time.After(2 * time.Second):
		t.Fatal("login action did not start SSO polling")
	}
	valid.Store(true)
	// Neither status-page polling nor a Dispatcher notification wakes this loop.
	deadline := time.Now().Add(8 * time.Second)
	for !g.Status().SessionReady && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if !g.Status().SessionReady {
		t.Fatalf("SSO transition was missed: %+v", g.Status())
	}
}
