package gateway

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os/exec"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gofrs/flock"
)

const (
	gatewayDownloadURL  = "https://download2.interactivebrokers.com/portal/clientportal.gw.zip"
	startupTimeout      = 30 * time.Second
	gatewayLogRetention = 14 * 24 * time.Hour
)

const (
	gatewayStateStopped      = "stopped"
	gatewayStateDetached     = "detached"
	gatewayStateInstalling   = "installing"
	gatewayStateStarting     = "starting"
	gatewayStateAuthRequired = "authentication_required"
	gatewayStateRunning      = "running"
	gatewayStateStopping     = "stopping"
	gatewayStateRestarting   = "restarting"
	gatewayStateUpgrading    = "upgrading"
	gatewayStateRollingBack  = "rolling_back"
	gatewayStateError        = "error"
)

var errManualAuthRequired = errors.New("manual authentication required")

// GatewayStatus is the public gateway state exposed via REST API.
type GatewayStatus struct {
	SessionSnapshot
	ProcessState      string `json:"process_state"`
	Running           bool   `json:"running"`
	Authenticated     bool   `json:"authenticated"`
	Account           string `json:"account"`
	Lifecycle         string `json:"lifecycle"`
	SessionAgeSeconds int64  `json:"session_age_seconds"`
	LoginMode         string `json:"login_mode"` // manual
	LoginURL          string `json:"login_url,omitempty"`
	AuthMessage       string `json:"auth_message,omitempty"`
	State             string `json:"state"`
	LastError         string `json:"last_error,omitempty"`
	StateUpdatedAt    string `json:"state_updated_at,omitempty"`
	InstalledVersion  string `json:"installed_version,omitempty"`
	PinnedVersion     string `json:"pinned_version,omitempty"`
	InstallVerified   bool   `json:"install_verified"`
	RollbackAvailable bool   `json:"rollback_available"`
}

// GatewayManager manages IBKR Client Portal Gateway lifecycle.
type GatewayManager struct {
	config     Config
	cmd        *exec.Cmd
	httpClient *http.Client

	mu                sync.Mutex
	opMu              sync.Mutex
	auditMu           sync.Mutex
	ctx               context.Context
	cancel            context.CancelFunc
	authenticatedAt   time.Time
	account           string
	monitorsStarted   bool
	monitorGeneration uint64
	restarting        atomic.Bool
	state             string
	lastError         string
	stateUpdatedAt    time.Time
	processLock       *flock.Flock
	release           gatewayRelease
	session           SessionSnapshot
	intentError       error
	wakeSession       chan struct{}
	loginInit         loginInitialization
	localFailures     int
	restartAttempts   []time.Time
}

func NewGatewayManager(cfg Config) *GatewayManager {
	cfg.GatewayLifecycle = NormalizeLifecycle(cfg.GatewayLifecycle)
	g := &GatewayManager{
		wakeSession:    make(chan struct{}, 1),
		session:        SessionSnapshot{DesiredState: desiredConnected, SSOState: sessionUnknown, SessionState: sessionUnknown},
		config:         cfg,
		httpClient:     newGatewayHTTPClient(cfg.GatewayURL, 10*time.Second),
		state:          gatewayStateStopped,
		stateUpdatedAt: time.Now().UTC(),
		release:        officialGatewayRelease,
	}
	g.loadIntent()
	return g
}

// BaseURL returns the private Client Portal Gateway origin used by this
// connection. Callers must still enforce that it resolves to loopback before
// exposing it through a reverse proxy.
func (g *GatewayManager) BaseURL() string {
	g.mu.Lock()
	defer g.mu.Unlock()
	return strings.TrimRight(g.config.GatewayURL, "/")
}

func (g *GatewayManager) setLifecycle(state string, err error) {
	g.mu.Lock()
	g.state = state
	if state != gatewayStateRunning && state != gatewayStateAuthRequired {
		g.invalidateSessionLocked(sessionUnknown)
		if state == gatewayStateStopped || state == gatewayStateDetached {
			g.session.SessionState = desiredStopped
		}
	}
	if err == nil {
		g.lastError = ""
	} else {
		g.lastError = sanitizeAuditValue(err.Error())
	}
	g.stateUpdatedAt = time.Now().UTC()
	g.mu.Unlock()
}

func (g *GatewayManager) failLifecycle(event string, err error) error {
	g.setLifecycle(gatewayStateError, err)
	g.audit(event, "error", err.Error())
	return err
}

// UpdateConfig replaces IBKR settings and should be followed by Reconnect().
func (g *GatewayManager) UpdateConfig(cfg Config) {
	g.mu.Lock()
	g.config = cfg
	g.httpClient = newGatewayHTTPClient(cfg.GatewayURL, 10*time.Second)
	g.mu.Unlock()
}

// Reconfigure safely stops the process using the old paths, releases the old
// manager lock, applies new settings, and starts under the new ownership scope.
func (g *GatewayManager) Reconfigure(cfg Config) error {
	g.opMu.Lock()
	defer g.opMu.Unlock()
	if err := g.acquireProcessLock(); err != nil {
		return err
	}
	g.cancelMonitoring()
	if err := g.stopProcess(); err != nil {
		return g.failLifecycle("gateway.reconfigure", err)
	}
	g.releaseProcessLock()
	g.mu.Lock()
	g.config = cfg
	g.httpClient = newGatewayHTTPClient(cfg.GatewayURL, 10*time.Second)
	g.mu.Unlock()
	g.clearSession(sessionUnknown)
	if err := g.acquireProcessLock(); err != nil {
		return err
	}
	if err := g.setIntent(g.Status().DesiredState); err != nil {
		return err
	}
	if g.Status().DesiredState != desiredConnected {
		g.clearSession(g.Status().DesiredState)
		g.mu.Lock()
		g.session.ProcessOnline = false
		g.mu.Unlock()
		g.setLifecycle(gatewayStateStopped, nil)
		return nil
	}
	if err := g.startLocked(context.Background()); err != nil {
		return g.failLifecycle("gateway.reconfigure", err)
	}
	g.audit("gateway.reconfigure", "success", "configuration applied")
	return nil
}

// Start ensures gateway is installed, running, authenticated, and monitored.
func (g *GatewayManager) Start(ctx context.Context) error {
	g.opMu.Lock()
	defer g.opMu.Unlock()
	if err := g.acquireProcessLock(); err != nil {
		return err
	}
	if err := g.setIntent(desiredConnected); err != nil {
		return err
	}
	return g.startLocked(ctx)
}

func (g *GatewayManager) startLocked(ctx context.Context) error {
	unlock, err := g.lockInstallation(ctx)
	if err != nil {
		return err
	}
	defer unlock()
	return g.startWithInstallationLock(ctx)
}

func (g *GatewayManager) startWithInstallationLock(ctx context.Context) error {
	g.cancelMonitoring()
	if err := g.acquireProcessLock(); err != nil {
		return g.failLifecycle("gateway.lock", err)
	}
	g.mu.Lock()
	if g.cancel != nil {
		g.cancel()
	}
	g.ctx, g.cancel = context.WithCancel(ctx)
	runCtx := g.ctx
	g.mu.Unlock()

	g.setLifecycle(gatewayStateInstalling, nil)
	if err := g.ensureInstalled(ctx); err != nil {
		return g.failLifecycle("gateway.install", fmt.Errorf("ensure installed: %w", err))
	}
	g.setLifecycle(gatewayStateStarting, nil)
	if err := g.ensureRunning(runCtx); err != nil {
		return g.failLifecycle("gateway.start", fmt.Errorf("ensure running: %w", err))
	}
	g.mu.Lock()
	g.session.ProcessOnline = true
	g.state = gatewayStateRunning
	g.mu.Unlock()
	// An expired login does not make starting a healthy Java process fail.
	if desired := g.Status().DesiredState; desired == desiredConnected {
		g.refreshSession(runCtx, true, false)
	} else {
		g.clearSession(desired)
	}
	g.StartTickler(runCtx)
	return nil
}

// Stop shuts down background tasks and kills the gateway process.
func (g *GatewayManager) Stop() {
	if err := g.StopGateway(false); err != nil {
		log.Printf("[IBKR] stop failed: %v", err)
	}
}

// Shutdown applies the configured process lifecycle. Server and Docker
// instances stop their Gateway; packaged desktop instances detach so the
// process can survive a sidecar restart. Keepalive stops during the gap;
// shutdown does not change the saved operator intent.
func (g *GatewayManager) Shutdown() error {
	g.opMu.Lock()
	defer g.opMu.Unlock()
	if err := g.acquireProcessLock(); err != nil {
		return err
	}
	g.mu.Lock()
	keepSession := g.config.GatewayLifecycle == LifecyclePersistent
	g.mu.Unlock()
	return g.stopGatewayLocked(keepSession)
}

// StartGateway ensures the IBKR gateway process is running and monitored.
func (g *GatewayManager) StartGateway(ctx context.Context) error {
	return g.Start(ctx)
}

// StopGateway stops monitoring and optionally kills the gateway process.
// When keepSession is true, the Java process keeps running without keepalive;
// the manager simply detaches. When false, the process is killed.
func (g *GatewayManager) StopGateway(keepSession bool) error {
	g.opMu.Lock()
	defer g.opMu.Unlock()
	if err := g.acquireProcessLock(); err != nil {
		return err
	}
	if err := g.setIntent(desiredStopped); err != nil {
		return err
	}
	return g.stopGatewayLocked(keepSession)
}

func (g *GatewayManager) stopGatewayLocked(keepSession bool) error {
	g.setLifecycle(gatewayStateStopping, nil)
	g.clearSession(desiredStopped)
	g.mu.Lock()
	if g.cancel != nil {
		g.cancel()
		g.cancel = nil
	}
	g.ctx = nil
	g.monitorsStarted = false
	g.monitorGeneration++
	g.mu.Unlock()

	if keepSession {
		g.mu.Lock()
		g.cmd = nil
		g.mu.Unlock()
		log.Println("[IBKR] detached from gateway (keepalive stopped)")
		g.releaseProcessLock()
		g.setLifecycle(gatewayStateDetached, nil)
		g.audit("gateway.stop", "detached", "process retained; keepalive stopped")
		return nil
	}

	if err := g.stopProcess(); err != nil {
		return g.failLifecycle("gateway.stop", err)
	}
	g.releaseProcessLock()
	g.clearSession(desiredStopped)
	g.setLifecycle(gatewayStateStopped, nil)
	g.audit("gateway.stop", "success", "gateway process stopped")
	return nil
}

// Status reads a snapshot. It never sends requests to IBKR or changes session state.
func (g *GatewayManager) Status() GatewayStatus {
	g.mu.Lock()
	status := GatewayStatus{
		SessionSnapshot: g.session,
		Running:         g.session.ProcessOnline, Authenticated: g.session.SessionReady,
		Account: g.account, Lifecycle: g.config.GatewayLifecycle, LoginMode: "manual",
		State: g.state, ProcessState: g.state, LastError: g.lastError, StateUpdatedAt: g.stateUpdatedAt.Format(time.RFC3339),
		PinnedVersion: g.release.Version,
	}
	if !g.authenticatedAt.IsZero() {
		status.SessionAgeSeconds = int64(time.Since(g.authenticatedAt).Seconds())
	}
	if status.ProcessState == gatewayStateAuthRequired {
		status.ProcessState = gatewayStateRunning
	}
	if status.ProcessState == gatewayStateRunning && !status.ProcessOnline {
		status.ProcessState = sessionUnknown
	}
	status.AuthMessage = status.SessionError
	gatewayDir := g.config.GatewayDir
	g.mu.Unlock()
	if manifest, err := readInstallManifest(gatewayDir); err == nil {
		status.InstalledVersion, status.InstallVerified = manifest.Version, manifest.Verified
	}
	status.RollbackAvailable = gatewayInstalled(rollbackGatewayDir(gatewayDir))
	return status
}

// Restart triggers a full gateway restart cycle without opening the login page.
func (g *GatewayManager) Restart() {
	g.restart()
}

// Reconnect manually triggers a full gateway restart cycle. Browser login is
// exposed by the daemon so this package never opens a browser on the host.
func (g *GatewayManager) Reconnect() error {
	return g.restart()
}

// Upgrade installs the pinned, SHA-256 verified Gateway release. The current
// installation is retained as a rollback candidate until the next upgrade.
func (g *GatewayManager) Upgrade(ctx context.Context) error {
	g.opMu.Lock()
	defer g.opMu.Unlock()
	unlock, lockErr := g.lockInstallation(ctx)
	if lockErr != nil {
		return lockErr
	}
	defer unlock()
	if err := g.checkInstallationIdle(); err != nil {
		return err
	}
	if err := g.acquireProcessLock(); err != nil {
		return g.failLifecycle("gateway.upgrade", err)
	}

	g.setLifecycle(gatewayStateUpgrading, nil)
	g.audit("gateway.upgrade", "started", "target="+g.release.Version)
	wasRunning := g.isOnline()
	g.cancelMonitoring()
	if err := g.stopProcess(); err != nil {
		return g.failLifecycle("gateway.upgrade", err)
	}
	if err := g.installVerifiedRelease(ctx); err != nil {
		if wasRunning {
			_ = g.startWithInstallationLock(context.WithoutCancel(ctx))
		}
		return g.failLifecycle("gateway.upgrade", err)
	}
	if g.Status().DesiredState == desiredStopped {
		g.clearSession(desiredStopped)
		g.setLifecycle(gatewayStateStopped, nil)
		return nil
	}
	if err := g.startWithInstallationLock(context.WithoutCancel(ctx)); err != nil {
		startErr := err
		_ = g.stopProcess()
		if rollbackErr := g.swapWithRollback(); rollbackErr != nil {
			return g.failLifecycle("gateway.upgrade", fmt.Errorf("new gateway failed: %v; rollback failed: %w", startErr, rollbackErr))
		}
		if restoreErr := g.startWithInstallationLock(context.Background()); restoreErr != nil {
			return g.failLifecycle("gateway.upgrade", fmt.Errorf("new gateway failed: %v; previous gateway restored but failed to start: %w", startErr, restoreErr))
		}
		warning := fmt.Errorf("upgrade failed and previous gateway was restored: %w", startErr)
		g.setLifecycle(gatewayStateRunning, warning)
		g.audit("gateway.upgrade", "rolled_back", warning.Error())
		return warning
	}
	g.audit("gateway.upgrade", "success", "version="+g.release.Version)
	return nil
}

// Rollback swaps the active installation with the retained previous version.
// The replaced version remains available, so another rollback acts as a
// controlled roll-forward.
func (g *GatewayManager) Rollback(ctx context.Context) error {
	g.opMu.Lock()
	defer g.opMu.Unlock()
	unlock, lockErr := g.lockInstallation(ctx)
	if lockErr != nil {
		return lockErr
	}
	defer unlock()
	if err := g.checkInstallationIdle(); err != nil {
		return err
	}
	if err := g.acquireProcessLock(); err != nil {
		return g.failLifecycle("gateway.rollback", err)
	}
	g.setLifecycle(gatewayStateRollingBack, nil)
	g.audit("gateway.rollback", "started", "manual rollback requested")
	g.cancelMonitoring()
	if err := g.stopProcess(); err != nil {
		return g.failLifecycle("gateway.rollback", err)
	}
	if err := g.swapWithRollback(); err != nil {
		return g.failLifecycle("gateway.rollback", err)
	}
	if g.Status().DesiredState == desiredStopped {
		g.clearSession(desiredStopped)
		g.setLifecycle(gatewayStateStopped, nil)
		return nil
	}
	if err := g.startWithInstallationLock(context.WithoutCancel(ctx)); err != nil {
		startErr := err
		_ = g.stopProcess()
		if swapErr := g.swapWithRollback(); swapErr != nil {
			return g.failLifecycle("gateway.rollback", fmt.Errorf("rollback version failed to start: %v; restore failed: %w", startErr, swapErr))
		}
		_ = g.startWithInstallationLock(context.Background())
		return g.failLifecycle("gateway.rollback", fmt.Errorf("rollback version failed to start: %w", startErr))
	}
	g.audit("gateway.rollback", "success", "previous gateway activated")
	return nil
}

func (g *GatewayManager) cancelMonitoring() {
	g.mu.Lock()
	if g.cancel != nil {
		g.cancel()
		g.cancel = nil
	}
	g.ctx = nil
	g.monitorsStarted = false
	g.monitorGeneration++
	g.mu.Unlock()
}

func (g *GatewayManager) EnsureAuthenticated(ctx context.Context) error {
	g.opMu.Lock()
	defer g.opMu.Unlock()
	g.refreshSession(ctx, false, false)
	if g.Status().SessionReady {
		return nil
	}
	return errManualAuthRequired
}

func (g *GatewayManager) resetSession() {
	g.mu.Lock()
	g.invalidateSessionLocked(sessionUnknown)
	g.mu.Unlock()
}

func (g *GatewayManager) restart() error {
	if !g.restarting.CompareAndSwap(false, true) {
		return fmt.Errorf("gateway restart already in progress")
	}
	defer g.restarting.Store(false)
	g.opMu.Lock()
	defer g.opMu.Unlock()
	if err := g.acquireProcessLock(); err != nil {
		return err
	}
	if g.Status().DesiredState == desiredStopped {
		if err := g.setIntent(desiredConnected); err != nil {
			return err
		}
	}
	return g.restartLocked()
}

func (g *GatewayManager) restartLocked() error {
	if err := g.acquireProcessLock(); err != nil {
		return err
	}
	log.Println("[IBKR] gateway restarting...")
	g.setLifecycle(gatewayStateRestarting, nil)
	g.audit("gateway.restart", "started", "health or reconnect requested")
	g.resetSession()
	g.mu.Lock()
	parent := context.Background()
	if g.ctx != nil {
		parent = context.WithoutCancel(g.ctx)
	}
	g.mu.Unlock()
	g.cancelMonitoring()
	if err := g.stopProcess(); err != nil {
		return g.failLifecycle("gateway.restart", err)
	}

	time.Sleep(3 * time.Second)
	if err := g.startLocked(parent); err != nil {
		return g.failLifecycle("gateway.restart", err)
	}
	g.audit("gateway.restart", "success", "gateway restarted")
	return nil
}
