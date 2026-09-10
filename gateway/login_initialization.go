package gateway

import (
	"fmt"
	"time"
)

const loginInitializationMaxAttempts = 3

// This permission is in memory, per instance, and created only by an explicit
// login/resume or takeover action. Browser success notifications cannot renew it.
// Access is protected by GatewayManager.mu; attempts are serialized by opMu.
type loginInitialization struct {
	waitingUntil time.Time
	deadline     time.Time
	nextAttempt  time.Time
	attempts     int
	exhausted    bool
}

func newLoginInitialization(now time.Time) loginInitialization {
	return loginInitialization{waitingUntil: now.Add(10 * time.Minute)}
}

func (l loginInitialization) pending() bool {
	return !l.waitingUntil.IsZero() || !l.deadline.IsZero()
}

func (l loginInitialization) active(now time.Time) bool {
	return !l.exhausted && (now.Before(l.waitingUntil) || now.Before(l.deadline))
}

// attempt is called only after SSO has been validated, immediately before init.
// The two-minute initialization window starts at that validation, not page load.
func (l *loginInitialization) attempt(now time.Time) (compete, wait bool, err error) {
	if !l.pending() {
		return false, false, nil
	}
	if !l.waitingUntil.IsZero() && !l.exhausted {
		if !now.Before(l.waitingUntil) {
			l.exhausted = true
		} else {
			l.waitingUntil = time.Time{}
			l.deadline = now.Add(2 * time.Minute)
		}
	}
	if l.exhausted || !now.Before(l.deadline) || l.attempts >= loginInitializationMaxAttempts {
		l.exhausted = true
		return false, false, fmt.Errorf("IBKR login initialization stopped after %d attempts: time or retry limit reached; open login again or explicitly take over the connection", l.attempts)
	}
	if now.Before(l.nextAttempt) {
		return true, true, nil
	}
	l.attempts++
	l.nextAttempt = now.Add(sessionRetryDelay(l.attempts))
	return true, false, nil
}
