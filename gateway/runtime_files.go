package gateway

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

func (g *GatewayManager) ensureGatewayConf() error {
	confFile := filepath.Join(g.config.GatewayDir, g.config.configFile())
	if !fileExists(confFile) {
		if err := copyFile(filepath.Join(g.config.GatewayDir, "root", "conf.yaml"), confFile); err != nil {
			return err
		}
	}
	if err := patchGatewayConf(confFile, g.config); err != nil {
		return err
	}
	return os.Chmod(confFile, 0o600)
}

// secureRuntimePermissions limits Gateway state to the current OS user. The
// IBKR distribution itself remains executable, while configuration, PID,
// certificates, caches and logs are treated as sensitive runtime data.
func (g *GatewayManager) secureRuntimePermissions() error {
	g.mu.Lock()
	gatewayDir := g.config.GatewayDir
	g.mu.Unlock()
	return secureGatewayRuntime(gatewayDir)
}

func secureGatewayRuntime(gatewayDir string) error {
	if err := os.Chmod(gatewayDir, 0o700); err != nil {
		return err
	}

	sensitiveFiles := []string{
		filepath.Join(gatewayDir, "root", "conf.yaml"),
		filepath.Join(gatewayDir, "root", "vertx.jks"),
		pidFile(gatewayDir),
		processRecordFile(gatewayDir),
		installManifestPath(gatewayDir),
	}
	for _, path := range sensitiveFiles {
		if err := os.Chmod(path, 0o600); err != nil && !os.IsNotExist(err) {
			return err
		}
	}

	for _, dir := range []string{
		filepath.Join(gatewayDir, "logs"),
		filepath.Join(gatewayDir, ".vertx"),
	} {
		if err := secureDataTree(dir); err != nil && !os.IsNotExist(err) {
			return err
		}
	}

	return pruneGatewayLogs(filepath.Join(gatewayDir, "logs"), time.Now().Add(-gatewayLogRetention))
}

func secureDataTree(root string) error {
	return filepath.WalkDir(root, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() {
			return os.Chmod(path, 0o700)
		}
		return os.Chmod(path, 0o600)
	})
}

func pruneGatewayLogs(logDir string, before time.Time) error {
	entries, err := os.ReadDir(logDir)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(strings.ToLower(entry.Name()), ".log") {
			continue
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		if info.ModTime().Before(before) {
			if err := os.Remove(filepath.Join(logDir, entry.Name())); err != nil {
				return err
			}
		}
	}
	return nil
}

// patchGatewayConf rewrites the fields in conf.yaml that the manager controls:
//   - listenPort      ← cfg.GatewayPort
//   - proxyRemoteHost ← cfg.GatewayProxyHost
//   - ips.allow list  ← cfg.GatewayAllowIPs
//
// All other fields are left untouched.
func patchGatewayConf(confFile string, cfg Config) error {
	data, err := os.ReadFile(confFile)
	if err != nil {
		return err
	}
	content := string(data)

	// --- listenPort ---
	rePort := regexp.MustCompile(`(?m)^(\s*)listenPort:\s*\d+\s*$`)
	if !rePort.MatchString(content) {
		return fmt.Errorf("listenPort not found in %s", confFile)
	}
	content = rePort.ReplaceAllStringFunc(content, func(line string) string {
		indent := rePort.FindStringSubmatch(line)[1]
		return indent + fmt.Sprintf("listenPort: %d", cfg.GatewayPort)
	})

	// --- proxyRemoteHost ---
	reProxy := regexp.MustCompile(`(?m)^(\s*)proxyRemoteHost:\s*\S+\s*$`)
	if reProxy.MatchString(content) {
		content = reProxy.ReplaceAllStringFunc(content, func(line string) string {
			indent := reProxy.FindStringSubmatch(line)[1]
			return indent + fmt.Sprintf("proxyRemoteHost: %q", cfg.GatewayProxyHost)
		})
	}

	// --- ips.allow ---
	// Replace the entire allow block:
	//     allow:
	//       - <ip>
	//       - <ip>
	reAllow := regexp.MustCompile(`(?m)^(\s*)allow:\s*\n(?:(\s+)-[^\n]*\n)*`)
	if reAllow.MatchString(content) && len(cfg.GatewayAllowIPs) > 0 {
		content = reAllow.ReplaceAllStringFunc(content, func(block string) string {
			// Detect indent of the "allow:" line itself.
			blockIndent := reAllow.FindStringSubmatch(block)[1]
			itemIndent := blockIndent + "  "
			var sb strings.Builder
			sb.WriteString(blockIndent + "allow:\n")
			for _, ip := range cfg.GatewayAllowIPs {
				sb.WriteString(itemIndent + "- " + ip + "\n")
			}
			return sb.String()
		})
	}

	return os.WriteFile(confFile, []byte(content), 0o600)
}

// patchListenPort is kept for backward compatibility with existing tests.
func patchListenPort(confFile string, port int) error {
	data, err := os.ReadFile(confFile)
	if err != nil {
		return err
	}
	re := regexp.MustCompile(`(?m)^(\s*)listenPort:\s*\d+\s*$`)
	if !re.MatchString(string(data)) {
		return fmt.Errorf("listenPort not found in %s", confFile)
	}
	updated := re.ReplaceAllStringFunc(string(data), func(line string) string {
		indent := re.FindStringSubmatch(line)[1]
		return indent + fmt.Sprintf("listenPort: %d", port)
	})
	return os.WriteFile(confFile, []byte(updated), 0o600)
}
