package gateway

import "context"

// RestoreConfiguration compensates a failed service configuration transaction.
// It restores process intent, not the broker session lost by a process restart.
func (g *GatewayManager) RestoreConfiguration(cfg Config, previous GatewayStatus) error {
	g.opMu.Lock()
	defer g.opMu.Unlock()
	g.cancelMonitoring()
	g.mu.Lock()
	owned := g.processLock != nil
	g.mu.Unlock()
	// A failed attempt to acquire the destination lock must never stop its owner.
	if owned {
		if err := g.stopProcess(); err != nil {
			return err
		}
		g.releaseProcessLock()
	}
	g.UpdateConfig(cfg)
	if err := g.acquireProcessLock(); err != nil {
		return err
	}
	if err := g.setIntent(previous.DesiredState); err != nil {
		return err
	}
	g.clearSession(previous.DesiredState)
	if previous.Running || previous.State == gatewayStateDetached {
		if err := g.startLocked(context.Background()); err != nil {
			return err
		}
		if previous.State == gatewayStateDetached {
			return g.stopGatewayLocked(true)
		}
		return nil
	}
	g.setLifecycle(gatewayStateStopped, nil)
	g.releaseProcessLock()
	return nil
}
