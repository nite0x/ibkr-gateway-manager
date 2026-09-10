package gateway

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/gofrs/flock"
)

// pidFile returns the path used to track the gateway's OS process ID.
func pidFile(gatewayDir string) string {
	return filepath.Join(gatewayDir, "gateway.pid")
}

func processRecordFile(gatewayDir string) string {
	return filepath.Join(gatewayDir, "gateway-process.json")
}

type gatewayProcessRecord struct {
	Version     int    `json:"version"`
	PID         int    `json:"pid"`
	WrapperPID  int    `json:"wrapper_pid,omitempty"`
	StartedAt   string `json:"started_at"`
	GatewayDir  string `json:"gateway_dir"`
	GatewayPort int    `json:"gateway_port"`
}

func (g *GatewayManager) acquireProcessLock() error {
	g.mu.Lock()
	if g.processLock != nil {
		g.mu.Unlock()
		return nil
	}
	gatewayDir := g.config.stateDir()
	g.mu.Unlock()

	if err := os.MkdirAll(gatewayDir, 0o700); err != nil {
		return err
	}
	lockPath := gatewayDir + ".manager.lock"
	lock := flock.New(lockPath, flock.SetPermissions(0o600))
	locked, err := lock.TryLock()
	if err != nil {
		return fmt.Errorf("lock gateway manager: %w", err)
	}
	if !locked {
		return fmt.Errorf("another process is already managing gateway directory %s", gatewayDir)
	}
	if err := os.Chmod(lockPath, 0o600); err != nil {
		_ = lock.Unlock()
		return fmt.Errorf("secure gateway manager lock: %w", err)
	}
	g.mu.Lock()
	g.processLock = lock
	g.mu.Unlock()
	return nil
}

func (g *GatewayManager) releaseProcessLock() {
	g.mu.Lock()
	lock := g.processLock
	g.processLock = nil
	g.mu.Unlock()
	if lock != nil {
		_ = lock.Unlock()
	}
}

func (g *GatewayManager) EnsureRunning(ctx context.Context) error {
	g.opMu.Lock()
	defer g.opMu.Unlock()
	if err := g.acquireProcessLock(); err != nil {
		return err
	}
	unlock, err := g.lockInstallation(ctx)
	if err != nil {
		return err
	}
	defer unlock()
	return g.ensureRunning(ctx)
}

func (g *GatewayManager) ensureRunning(ctx context.Context) error {
	// Reuse a validated Gateway that survived a persistent desktop shutdown.
	// Recovery also migrates the old numeric PID file by resolving the process
	// that actually owns this connection's configured listening port.
	if record, err := g.loadOrRecoverOwnedProcess(); err == nil {
		log.Printf("[IBKR] reusing existing gateway process (pid=%d)", record.PID)
		if g.isOnline() || g.waitUntilOnline(ctx) {
			return nil
		}
		if err := terminateProcess(record.PID); err != nil {
			return fmt.Errorf("stop unresponsive gateway process %d: %w", record.PID, err)
		}
		g.removeProcessRecord()
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}

	// Never terminate an arbitrary process merely because it occupies the
	// configured port. The operator must resolve that conflict explicitly.
	if portInUse(g.config.GatewayPort) {
		return fmt.Errorf("gateway port %d is occupied by an unowned process", g.config.GatewayPort)
	}

	if !gatewayInstalled(g.config.GatewayDir) {
		return fmt.Errorf("gateway not installed at %s", g.config.GatewayDir)
	}
	if err := g.ensureGatewayConf(); err != nil {
		return fmt.Errorf("configure gateway: %w", err)
	}

	runJar := filepath.Join(g.config.GatewayDir, "root", "run.jar")
	runSh := filepath.Join(g.config.GatewayDir, "bin", "run.sh")

	var cmd *exec.Cmd
	switch {
	case fileExists(runJar):
		cmd = exec.Command("java", "-jar", runJar, g.config.configFile())
	case fileExists(runSh):
		cmd = exec.Command("bash", "bin/run.sh", g.config.configFile())
	default:
		return fmt.Errorf("gateway startup script missing in %s", g.config.GatewayDir)
	}
	cmd.Dir = g.config.GatewayDir
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	isolateGatewayProcess(cmd)

	if err := cmd.Start(); err != nil {
		return fmt.Errorf("start gateway: %w", err)
	}

	// Store the wrapper temporarily. Once the listener is ready this is replaced
	// by the actual Java PID, while WrapperPID remains available for cleanup.
	wrapperPID := cmd.Process.Pid
	if err := writePIDFile(pidFile(g.config.stateDir()), wrapperPID); err != nil {
		_ = terminateGatewayProcessGroup(wrapperPID)
		_ = cmd.Wait()
		return fmt.Errorf("write gateway pid file: %w", err)
	}

	g.mu.Lock()
	g.cmd = cmd
	g.mu.Unlock()

	log.Printf("[IBKR] gateway wrapper started (pid=%d)", wrapperPID)
	if !g.waitUntilOnline(ctx) {
		_ = terminateGatewayProcessGroup(wrapperPID)
		_ = cmd.Wait()
		g.removeProcessRecord()
		return fmt.Errorf("gateway did not become ready within %s", startupTimeout)
	}

	pid, err := g.findGatewayListener()
	if err != nil {
		_ = terminateGatewayProcessGroup(wrapperPID)
		_ = cmd.Wait()
		g.removeProcessRecord()
		return fmt.Errorf("identify gateway Java process: %w", err)
	}
	record, err := g.newProcessRecord(pid, wrapperPID)
	if err != nil {
		_ = terminateGatewayProcessGroup(wrapperPID)
		_ = cmd.Wait()
		g.removeProcessRecord()
		return fmt.Errorf("record gateway Java process: %w", err)
	}
	if err := g.writeProcessRecord(record); err != nil {
		_ = terminateGatewayProcessGroup(wrapperPID)
		_ = cmd.Wait()
		g.removeProcessRecord()
		return fmt.Errorf("write gateway process record: %w", err)
	}

	stateDir := g.config.stateDir()
	go func() {
		_ = cmd.Wait()
		g.mu.Lock()
		if g.cmd == cmd {
			g.cmd = nil
		}
		g.mu.Unlock()
		if !processAlive(record.PID) {
			removeProcessRecordIfPID(stateDir, record.PID)
		}
	}()

	log.Printf("[IBKR] gateway Java process started (pid=%d, wrapper_pid=%d)", pid, wrapperPID)
	return nil
}

func (g *GatewayManager) stopProcess() (stopErr error) {
	if err := g.acquireProcessLock(); err != nil {
		return err
	}
	defer func() {
		if stopErr == nil {
			g.mu.Lock()
			g.session.ProcessOnline = false
			g.mu.Unlock()
		}
	}()
	g.mu.Lock()
	cmd := g.cmd
	g.cmd = nil
	g.mu.Unlock()

	record, err := g.loadOrRecoverOwnedProcess()
	if err == nil {
		if err := terminateProcess(record.PID); err != nil {
			return err
		}
		// The run.sh wrapper normally exits when Java exits. If it does not,
		// terminate only the isolated process group created by this manager.
		if record.WrapperPID > 1 && processAlive(record.WrapperPID) {
			_ = terminateGatewayProcessGroup(record.WrapperPID)
		}
		g.removeProcessRecord()
		log.Printf("[IBKR] gateway process stopped (pid=%d)", record.PID)
		return nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if cmd != nil && cmd.Process != nil && processAlive(cmd.Process.Pid) {
		if err := terminateGatewayProcessGroup(cmd.Process.Pid); err != nil {
			return err
		}
	}
	g.removeProcessRecord()
	return nil
}

// gatewayProcessMatches validates both the command line and working directory
// before the manager adopts or terminates a PID loaded from disk.
func (g *GatewayManager) gatewayProcessMatches(pid int) bool {
	out, err := exec.Command("ps", "-p", strconv.Itoa(pid), "-o", "command=").Output()
	if err != nil {
		return false
	}
	command := strings.ToLower(string(out))
	if !strings.Contains(command, "clientportal.gw") &&
		!strings.Contains(command, "root/run.jar") &&
		!strings.Contains(command, "bin/run.sh") {
		return false
	}

	configArg := regexp.MustCompile(`(?:^|[\s"'])(?:\.\./)?` + regexp.QuoteMeta(g.config.configFile()) + `(?:[\s"']|$)`)
	if !configArg.MatchString(string(out)) {
		return false
	}
	cwdOutput, err := exec.Command("lsof", "-a", "-p", strconv.Itoa(pid), "-d", "cwd", "-Fn").Output()
	if err != nil {
		return false
	}
	for _, line := range strings.Split(string(cwdOutput), "\n") {
		if !strings.HasPrefix(line, "n") {
			continue
		}
		cwd, cwdErr := filepath.EvalSymlinks(strings.TrimPrefix(line, "n"))
		gatewayDir, dirErr := filepath.EvalSymlinks(g.config.GatewayDir)
		return cwdErr == nil && dirErr == nil && filepath.Clean(cwd) == filepath.Clean(gatewayDir)
	}
	return false
}

func (g *GatewayManager) findGatewayListener() (int, error) {
	out, err := exec.Command(
		"lsof", "-nP", "-t", "-iTCP:"+strconv.Itoa(g.config.GatewayPort), "-sTCP:LISTEN",
	).Output()
	if err != nil {
		return 0, os.ErrNotExist
	}
	for _, value := range strings.Fields(string(out)) {
		pid, parseErr := strconv.Atoi(value)
		if parseErr == nil && g.gatewayProcessMatches(pid) && processListensOnPort(pid, g.config.GatewayPort) {
			return pid, nil
		}
	}
	return 0, os.ErrNotExist
}

func (g *GatewayManager) newProcessRecord(pid, wrapperPID int) (gatewayProcessRecord, error) {
	startedAt, err := processStartSignature(pid)
	if err != nil {
		return gatewayProcessRecord{}, err
	}
	gatewayDir, err := filepath.EvalSymlinks(g.config.GatewayDir)
	if err != nil {
		return gatewayProcessRecord{}, err
	}
	return gatewayProcessRecord{
		Version:     1,
		PID:         pid,
		WrapperPID:  wrapperPID,
		StartedAt:   startedAt,
		GatewayDir:  filepath.Clean(gatewayDir),
		GatewayPort: g.config.GatewayPort,
	}, nil
}

func (g *GatewayManager) writeProcessRecord(record gatewayProcessRecord) error {
	data, err := json.Marshal(record)
	if err != nil {
		return err
	}
	path := processRecordFile(g.config.stateDir())
	temporary := path + ".tmp"
	if err := os.WriteFile(temporary, data, 0o600); err != nil {
		return err
	}
	if err := os.Rename(temporary, path); err != nil {
		_ = os.Remove(temporary)
		return err
	}
	if err := os.Chmod(path, 0o600); err != nil {
		return err
	}
	return writePIDFile(pidFile(g.config.stateDir()), record.PID)
}

func (g *GatewayManager) loadOrRecoverOwnedProcess() (gatewayProcessRecord, error) {
	record, err := readProcessRecord(processRecordFile(g.config.stateDir()))
	if err == nil {
		if !processAlive(record.PID) {
			g.removeProcessRecord()
			return gatewayProcessRecord{}, os.ErrNotExist
		}
		if err := g.validateProcessRecord(record); err != nil {
			return gatewayProcessRecord{}, err
		}
		return record, nil
	}
	if !os.IsNotExist(err) {
		return gatewayProcessRecord{}, fmt.Errorf("read gateway process record: %w", err)
	}

	// Backward compatibility: old versions stored only a PID. It may identify
	// the run.sh wrapper, so prefer it only when it owns the configured port.
	if pid, pidErr := readPIDFile(pidFile(g.config.stateDir())); pidErr == nil &&
		processAlive(pid) && g.gatewayProcessMatches(pid) && processListensOnPort(pid, g.config.GatewayPort) {
		record, err = g.newProcessRecord(pid, 0)
	} else {
		pid, listenerErr := g.findGatewayListener()
		if listenerErr != nil {
			return gatewayProcessRecord{}, os.ErrNotExist
		}
		record, err = g.newProcessRecord(pid, 0)
	}
	if err != nil {
		return gatewayProcessRecord{}, err
	}
	if err := g.writeProcessRecord(record); err != nil {
		return gatewayProcessRecord{}, err
	}
	log.Printf("[IBKR] recovered gateway ownership (pid=%d, port=%d)", record.PID, record.GatewayPort)
	return record, nil
}

func (g *GatewayManager) validateProcessRecord(record gatewayProcessRecord) error {
	if record.Version != 1 || record.PID <= 1 {
		return fmt.Errorf("invalid gateway process record")
	}
	if record.GatewayPort != g.config.GatewayPort {
		return fmt.Errorf("gateway process record port %d does not match configured port %d", record.GatewayPort, g.config.GatewayPort)
	}
	gatewayDir, err := filepath.EvalSymlinks(g.config.GatewayDir)
	if err != nil || filepath.Clean(record.GatewayDir) != filepath.Clean(gatewayDir) {
		return fmt.Errorf("gateway process record directory does not match configured directory")
	}
	if !g.gatewayProcessMatches(record.PID) || !processListensOnPort(record.PID, record.GatewayPort) {
		return fmt.Errorf("gateway process %d does not match its recorded command, directory, and port", record.PID)
	}
	startedAt, err := processStartSignature(record.PID)
	if err != nil || startedAt != record.StartedAt {
		return fmt.Errorf("gateway process %d start identity changed", record.PID)
	}
	return nil
}

func (g *GatewayManager) removeProcessRecord() {
	_ = os.Remove(pidFile(g.config.stateDir()))
	_ = os.Remove(processRecordFile(g.config.stateDir()))
}

func removeProcessRecordIfPID(stateDir string, pid int) {
	record, err := readProcessRecord(processRecordFile(stateDir))
	if err == nil && record.PID == pid {
		_ = os.Remove(pidFile(stateDir))
		_ = os.Remove(processRecordFile(stateDir))
	}
}

func readProcessRecord(path string) (gatewayProcessRecord, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return gatewayProcessRecord{}, err
	}
	var record gatewayProcessRecord
	if err := json.Unmarshal(data, &record); err != nil {
		return gatewayProcessRecord{}, err
	}
	return record, nil
}

func processStartSignature(pid int) (string, error) {
	out, err := exec.Command("ps", "-p", strconv.Itoa(pid), "-o", "lstart=").Output()
	if err != nil {
		return "", err
	}
	value := strings.TrimSpace(string(out))
	if value == "" {
		return "", fmt.Errorf("process %d has no start time", pid)
	}
	return value, nil
}

func processListensOnPort(pid, port int) bool {
	if pid <= 1 || port <= 0 {
		return false
	}
	out, err := exec.Command(
		"lsof", "-nP", "-a", "-p", strconv.Itoa(pid),
		"-iTCP:"+strconv.Itoa(port), "-sTCP:LISTEN", "-t",
	).Output()
	return err == nil && strings.TrimSpace(string(out)) == strconv.Itoa(pid)
}

func terminateProcess(pid int) error {
	proc, err := os.FindProcess(pid)
	if err != nil {
		return err
	}
	if err := proc.Signal(syscall.SIGTERM); err != nil && processAlive(pid) {
		return err
	}
	deadline := time.Now().Add(5 * time.Second)
	for processAlive(pid) && time.Now().Before(deadline) {
		time.Sleep(100 * time.Millisecond)
	}
	if !processAlive(pid) {
		return nil
	}
	return proc.Kill()
}

func portInUse(port int) bool {
	if port <= 0 {
		return false
	}
	conn, err := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)), 300*time.Millisecond)
	if err != nil {
		return false
	}
	_ = conn.Close()
	return true
}

// writePIDFile atomically writes pid to path.
func writePIDFile(path string, pid int) error {
	if err := os.WriteFile(path, []byte(strconv.Itoa(pid)), 0o600); err != nil {
		return err
	}
	return os.Chmod(path, 0o600)
}

// readPIDFile reads a PID from path.
func readPIDFile(path string) (int, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return 0, err
	}
	return strconv.Atoi(strings.TrimSpace(string(data)))
}

// processAlive reports whether the process with the given PID is still running.
func processAlive(pid int) bool {
	proc, err := os.FindProcess(pid)
	if err != nil {
		return false
	}
	// os.FindProcess always succeeds on Unix; send signal 0 to test liveness.
	return proc.Signal(syscall.Signal(0)) == nil
}
