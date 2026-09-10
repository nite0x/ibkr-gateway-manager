//go:build darwin || linux

package gateway

import (
	"errors"
	"os/exec"
	"syscall"
)

// isolateGatewayProcess keeps terminal Ctrl+C signals sent to the manager from also
// reaching the Gateway. Managed shutdown still terminates this exact group.
func isolateGatewayProcess(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
}

func terminateGatewayProcessGroup(groupLeaderPID int) error {
	if groupLeaderPID <= 1 {
		return nil
	}
	err := syscall.Kill(-groupLeaderPID, syscall.SIGKILL)
	if errors.Is(err, syscall.ESRCH) {
		return nil
	}
	return err
}
