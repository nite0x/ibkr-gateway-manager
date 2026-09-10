package gateway

import (
	"encoding/json"
	"log"
	"os"
	"regexp"
	"strings"
	"time"
)

const (
	gatewayAuditFilenameSuffix = ".audit.jsonl"
	gatewayAuditMaxSize        = 5 << 20
)

var (
	auditHeaderSecretPattern = regexp.MustCompile(`(?i)(authorization|cookie)(\s*[:=]\s*)([^,;]+)`)
	auditSecretPattern       = regexp.MustCompile(`(?i)(password|totp|access[_-]?token|token)(\s*[:=]\s*)([^\s,;]+)`)
	auditURLUserInfoPattern  = regexp.MustCompile(`://[^/@\s]+@`)
)

type gatewayAuditEntry struct {
	Timestamp string `json:"timestamp"`
	Event     string `json:"event"`
	Result    string `json:"result"`
	Detail    string `json:"detail,omitempty"`
}

func (g *GatewayManager) audit(event, result, detail string) {
	entry := gatewayAuditEntry{
		Timestamp: time.Now().UTC().Format(time.RFC3339),
		Event:     sanitizeAuditValue(event),
		Result:    sanitizeAuditValue(result),
		Detail:    sanitizeAuditValue(detail),
	}
	data, err := json.Marshal(entry)
	if err != nil {
		return
	}

	g.auditMu.Lock()
	defer g.auditMu.Unlock()
	g.mu.Lock()
	gatewayDir := g.config.stateDir()
	g.mu.Unlock()
	path := gatewayDir + gatewayAuditFilenameSuffix
	if info, err := os.Stat(path); err == nil && info.Size() >= gatewayAuditMaxSize {
		rotated := path + ".1"
		_ = os.Remove(rotated)
		if err := os.Rename(path, rotated); err == nil {
			_ = os.Chmod(rotated, 0o600)
		}
	}
	file, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		log.Printf("[IBKR] audit log unavailable: %v", err)
		return
	}
	defer file.Close()
	_ = file.Chmod(0o600)
	_, _ = file.Write(append(data, '\n'))
}

func sanitizeAuditValue(value string) string {
	value = strings.ReplaceAll(value, "\r", " ")
	value = strings.ReplaceAll(value, "\n", " ")
	value = auditHeaderSecretPattern.ReplaceAllString(value, "$1$2[REDACTED]")
	value = auditSecretPattern.ReplaceAllString(value, "$1$2[REDACTED]")
	return auditURLUserInfoPattern.ReplaceAllString(value, "://[REDACTED]@")
}
