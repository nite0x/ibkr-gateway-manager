package gateway

import (
	"context"
	"math/rand/v2"
	"net/http"
	"time"
)

// StartTickler starts the single supervisor for this instance. Startup and all
// lifecycle operations hold opMu; the flag prevents duplicate supervisor loops.
func (g *GatewayManager) StartTickler(ctx context.Context) {
	g.mu.Lock()
	if g.monitorsStarted {
		g.mu.Unlock()
		return
	}
	g.monitorsStarted = true
	g.monitorGeneration++
	generation := g.monitorGeneration
	g.mu.Unlock()
	go func() {
		defer func() {
			g.mu.Lock()
			defer g.mu.Unlock()
			if g.monitorGeneration != generation {
				return
			}
			g.monitorsStarted = false
			if ctx.Err() != nil && g.session.DesiredState == desiredConnected {
				g.invalidateSessionLocked(sessionUnknown)
				g.session.Stale = true
			}
		}()
		delay := g.nextSessionDelay()
		timer := time.NewTimer(delay)
		defer timer.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-timer.C:
			case <-g.wakeSession:
			}
			g.opMu.Lock()
			if ctx.Err() != nil {
				g.opMu.Unlock()
				return
			}
			if err := g.secureRuntimePermissions(); err != nil {
				g.audit("gateway.permissions", "error", err.Error())
			}
			g.refreshSession(ctx, true, false)
			if g.shouldRestartProcess(ctx) {
				// Holding opMu and checking the originating context prevents a stale
				// monitor from restarting a process after StopGateway or Shutdown.
				if err := g.restartLocked(); err != nil {
					g.mu.Lock()
					g.session.SessionError = err.Error()
					g.mu.Unlock()
					// A failed restart may cancel this monitor before launching a replacement.
					g.ensureSessionMonitor()
				}
				g.opMu.Unlock()
				return
			}
			delay = g.nextSessionDelay()
			g.opMu.Unlock()
			if !timer.Stop() {
				select {
				case <-timer.C:
				default:
				}
			}
			timer.Reset(delay)
		}
	}()
}

func (g *GatewayManager) nextSessionDelay() time.Duration {
	g.mu.Lock()
	s := g.session
	since := g.stateUpdatedAt
	loginInit := g.loginInit.active(time.Now())
	g.mu.Unlock()
	if loginInit {
		return 5 * time.Second
	}
	switch s.SessionState {
	case sessionReady, sessionCompeting, sessionTakeoverRequired, desiredLoggedOut, desiredStopped:
		return time.Minute
	case sessionLoginRequired:
		if time.Since(since) > 10*time.Minute {
			return time.Minute
		}
		return 5 * time.Second
	default:
		delay := sessionRetryDelay(s.RetryCount)
		return delay + time.Duration(rand.Int64N(int64(delay/10)+1))
	}
}

func (g *GatewayManager) shouldRestartProcess(ctx context.Context) bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	if ctx.Err() != nil || g.session.DesiredState != desiredConnected || g.localFailures < 3 {
		return false
	}
	now := time.Now()
	recent := g.restartAttempts[:0]
	for _, t := range g.restartAttempts {
		if now.Sub(t) < 15*time.Minute {
			recent = append(recent, t)
		}
	}
	g.restartAttempts = recent
	if len(recent) >= 3 {
		g.session.SessionError = "local gateway restart limit reached; retrying after cooldown"
		return false
	}
	g.restartAttempts = append(g.restartAttempts, now)
	g.localFailures = 0
	return true
}

// StartHealthMonitor is retained for embedders; health and keepalive now share one loop.
func (g *GatewayManager) StartHealthMonitor(ctx context.Context) { g.StartTickler(ctx) }

// tickle is retained as a low-level request helper for existing package callers.
func (g *GatewayManager) tickle() {
	_, _ = g.sessionRequest(context.Background(), http.MethodPost, "/tickle", nil)
}
