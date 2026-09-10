package gateway

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/gofrs/flock"
)

// Installation changes and process startup share one cross-process lock. PID
// records and lifecycle locks remain private to each instance's state directory.
func (g *GatewayManager) lockInstallation(ctx context.Context) (func(), error) {
	dir := filepath.Clean(g.config.GatewayDir)
	if err := os.MkdirAll(filepath.Dir(dir), 0o700); err != nil {
		return nil, err
	}
	if resolved, err := filepath.EvalSymlinks(dir); err == nil {
		dir = resolved
	}
	lock := flock.New(dir+".install.lock", flock.SetPermissions(0o600))
	locked, err := lock.TryLockContext(ctx, 100*time.Millisecond)
	if err != nil {
		return nil, err
	}
	if !locked {
		return nil, fmt.Errorf("gateway installation is busy")
	}
	return func() { _ = lock.Unlock() }, nil
}

// A detached Java process holds no manager lock. Inspect working directories
// as well so an upgrade cannot replace files beneath a persistent session.
func (g *GatewayManager) checkInstallationIdle() error {
	if !gatewayInstalled(g.config.GatewayDir) {
		return nil
	}
	ownPID, wrapperPID := 0, 0
	if record, err := g.loadOrRecoverOwnedProcess(); err == nil {
		ownPID, wrapperPID = record.PID, record.WrapperPID
	} else if !os.IsNotExist(err) {
		return err
	}
	out, err := exec.Command("lsof", "-a", "+d", g.config.GatewayDir, "-d", "cwd", "-t").Output()
	if err != nil {
		if exit, ok := err.(*exec.ExitError); !ok || exit.ExitCode() != 1 || len(exit.Stderr) != 0 {
			return fmt.Errorf("inspect shared gateway processes: %w", err)
		}
	}
	for _, value := range strings.Fields(string(out)) {
		pid, err := strconv.Atoi(value)
		if err != nil {
			return fmt.Errorf("invalid process ID from lsof: %q", value)
		}
		if pid != ownPID && pid != wrapperPID {
			return fmt.Errorf("shared gateway installation is in use by process %d; stop other instances before upgrading or rolling back", pid)
		}
	}
	return nil
}

// Keep instance configs (including operator-created YAML files) across a
// release swap, including conf.yaml used by legacy instances.
func preserveGatewayConfigs(source, destination string) error {
	entries, err := os.ReadDir(filepath.Join(source, "root"))
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".yaml") {
			continue
		}
		if err := copyFile(filepath.Join(source, "root", entry.Name()), filepath.Join(destination, "root", entry.Name())); err != nil {
			return err
		}
		if err := os.Chmod(filepath.Join(destination, "root", entry.Name()), 0o600); err != nil {
			return err
		}
	}
	return nil
}
