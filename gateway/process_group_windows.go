//go:build windows

package gateway

import (
	"os"
	"os/exec"
)

func isolateGatewayProcess(_ *exec.Cmd) {}

func terminateGatewayProcessGroup(pid int) error {
	process, err := os.FindProcess(pid)
	if err != nil {
		return err
	}
	return process.Kill()
}
