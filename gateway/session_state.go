package gateway

import "time"

const (
	desiredConnected        = "connected"
	desiredLoggedOut        = "logged_out"
	desiredStopped          = "stopped"
	sessionUnknown          = "unknown"
	sessionReady            = "ready"
	sessionRecovering       = "recovering"
	sessionInitializing     = "initializing"
	sessionLoginRequired    = "login_required"
	sessionCompeting        = "competing"
	sessionTakeoverRequired = "takeover_required"
	ssoValid                = "valid"
	ssoExpired              = "expired"
)

func validDesiredState(state string) bool {
	return state == desiredConnected || state == desiredLoggedOut || state == desiredStopped
}

// invalidateSessionLocked is the common transition out of an observed ready
// session. Keep historical check times and generation, but never retain account
// identity, auth age or connection flags after invalidation. Requires mu.
func (g *GatewayManager) invalidateSessionLocked(state string) {
	g.loginInit = loginInitialization{}
	g.session.SessionState = state
	g.session.SSOState = sessionUnknown
	g.session.SessionReady = false
	g.session.Connected, g.session.Established, g.session.Competing = false, false, false
	g.session.NextRetryAt = ""
	g.account, g.authenticatedAt = "", time.Time{}
}
