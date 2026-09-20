package main

import (
	"fmt"
	"os"
	"time"

	"github.com/spf13/cobra"

	"warden/internal/audit"
)

// armCmd and disarmCmd gate watch's auto-restore behind an explicit,
// human-triggered switch. The box comes up disarmed (no marker file) right
// after install.sh, since that's exactly the window a team spends hardening
// the same config files watch would otherwise be reverting out from under
// them every few minutes. Arm once hardening is actually done; disarm again
// before any planned maintenance window that touches a watched file.
func armCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "arm",
		Short: "Lock in the current config-tier state and turn on auto-restore",
		Long: `Takes a fresh config-tier snapshot of exactly what's on disk right now,
then turns on watch's auto-restore for future drift.

Run this once, after the box has been hardened, not before — anything
written before arm runs becomes the enforced "known good" state, so
arming mid-hardening would lock in a still-vulnerable configuration.
Before that point, watch still runs and still flags anything sensitive,
it just won't overwrite a SafeAutoRestore path out from under someone
still editing it.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runArm()
		},
	}
}

func disarmCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "disarm",
		Short: "Turn off auto-restore (e.g. ahead of a planned maintenance window)",
		Long: `Turns off watch's auto-restore without touching the existing snapshot
lineage. Confirm-first paths (passwd, shadow, sudoers, sshd_config, ...)
keep getting flagged either way — disarm only affects whether a drifted
SafeAutoRestore path gets overwritten.

Run 'warden arm' again once the maintenance window is over, so it takes
a fresh snapshot of the post-maintenance state before re-enabling.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runDisarm()
		},
	}
}

func runArm() error {
	p, err := loadPaths()
	if err != nil {
		return err
	}

	// Lock in exactly what's on disk right now as the enforced baseline,
	// not whatever snapshot's own timer last happened to catch.
	if err := runSnapshot(tierConfig); err != nil {
		return fmt.Errorf("arm: snapshot before arming: %w", err)
	}

	armedAt := time.Now().UTC().Format(time.RFC3339)
	if err := os.WriteFile(p.armedMarkerPath, []byte(armedAt+"\n"), 0o600); err != nil {
		return fmt.Errorf("arm: write marker: %w", err)
	}

	log, err := audit.New(p.auditLogPath)
	if err != nil {
		return err
	}
	defer log.Close()
	if err := log.Log("arm", "armed", map[string]any{"at": armedAt}); err != nil {
		return err
	}

	fmt.Println("armed: auto-restore is now on. watch will revert future drift in SafeAutoRestore paths.")
	return nil
}

func runDisarm() error {
	p, err := loadPaths()
	if err != nil {
		return err
	}

	if err := os.Remove(p.armedMarkerPath); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("disarm: remove marker: %w", err)
	}

	log, err := audit.New(p.auditLogPath)
	if err != nil {
		return err
	}
	defer log.Close()
	if err := log.Log("arm", "disarmed", nil); err != nil {
		return err
	}

	fmt.Println("disarmed: auto-restore is off. confirm-first paths are still flagged. run 'warden arm' when done.")
	return nil
}

// isArmed reports whether auto-restore is currently on. Any error other
// than the marker simply not existing yet is surfaced, rather than quietly
// treated as disarmed, since a permissions problem here should be loud, not
// silently degrade watch's behavior.
func isArmed(p paths) (bool, error) {
	_, err := os.Stat(p.armedMarkerPath)
	if os.IsNotExist(err) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("check armed state: %w", err)
	}
	return true, nil
}
