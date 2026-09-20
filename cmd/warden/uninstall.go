package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"
)

// uninstallCmd reverses everything install.sh set up, as a way back to a
// clean box if setup goes wrong — a full transactional install (roll back
// automatically on any failure partway through) would need every step in
// install.sh to be independently reversible and the two scripts kept in
// exact lockstep forever; this is the more honest version of that: one
// explicit command that undoes it all, callable either after a failed
// setup or any time before arming.
//
// Refuses once the box is armed unless --force is passed — see the Long
// help text below for why that line is drawn at arm, not at install.
func uninstallCmd() *cobra.Command {
	var force bool

	cmd := &cobra.Command{
		Use:   "uninstall",
		Short: "Remove everything install.sh set up on this box",
		Long: `Reverses install.sh: stops and deletes every systemd timer (watch,
sentinel, both snapshot tiers, replicate), the cron fallback entry, the
sudoers rule, the dedicated access-layer account, the installed binary
and its hidden spare copy, and all local state under /var/lib/<name>
(manifests, the backup store, the audit log, the static secret). Off-box
replicas already pushed to a peer box are never touched — recovering
from one later still works the same way docs/DEPLOYMENT.md describes.

Refuses to run on an armed box unless --force is given. Before 'warden
arm', nothing here is load-bearing yet — this is a plain "start over"
button for a setup that went wrong. After arm, the team's actual
hardening is presumably riding on this box staying defended, so tearing
it down needs to be a deliberate choice, not a habit left over from
testing.

This removes its own binary as its last step, which is safe on Linux —
the running process keeps executing from the file it already has open
until it exits — but leaves nothing named 'warden' on this box to run
anything else with afterward.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runUninstall(force)
		},
	}
	cmd.Flags().BoolVar(&force, "force", false, "remove even if the box is currently armed")
	return cmd
}

func runUninstall(force bool) error {
	p, err := loadPaths()
	if err != nil {
		return err
	}
	armed, err := isArmed(p)
	if err != nil {
		return err
	}
	if armed && !force {
		return fmt.Errorf("uninstall: this box is armed — hardening is presumably riding on it now; re-run with --force if you really mean to remove Warden anyway")
	}

	path, err := installPath()
	if err != nil {
		return err
	}
	binName, err := binaryName()
	if err != nil {
		return err
	}
	opUser, err := opmenuUser()
	if err != nil {
		return err
	}

	fmt.Println("==> Stopping and removing systemd timers")
	for _, suffix := range []string{"-watch", "-sentinel", "-snap-cfg", "-snap-data", "-replicate"} {
		removeSystemdTimer(binName + suffix)
	}
	if err := runSystemctl("daemon-reload"); err != nil {
		fmt.Fprintf(os.Stderr, "warning: %v\n", err)
	}

	if sentinelUnit, err := sentinelUnitName(); err == nil {
		fmt.Println("==> Removing cron fallback entry")
		if err := removeCronEntryFile(cronSpoolPath(), cronMarker(sentinelUnit)); err != nil {
			fmt.Fprintf(os.Stderr, "warning: %v\n", err)
		}
	}

	sudoersPath := sudoersDropInPath(opUser)
	fmt.Println("==> Removing sudoers rule:", sudoersPath)
	if err := os.Remove(sudoersPath); err != nil && !os.IsNotExist(err) {
		fmt.Fprintf(os.Stderr, "warning: remove %s: %v\n", sudoersPath, err)
	}

	fmt.Println("==> Removing access-layer account:", opUser)
	if out, err := exec.Command("userdel", "-r", opUser).CombinedOutput(); err != nil {
		fmt.Fprintf(os.Stderr, "warning: userdel %s: %v: %s\n", opUser, err, out)
	}

	// p.dataDir (/var/lib/<name>) already contains the spare binary
	// (spareBinaryPath), so removing it covers that too — no separate step.
	fmt.Println("==> Removing local state:", p.dataDir)
	if err := os.RemoveAll(p.dataDir); err != nil {
		fmt.Fprintf(os.Stderr, "warning: remove %s: %v\n", p.dataDir, err)
	}

	fmt.Println("==> Removing installed binary:", path)
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		fmt.Fprintf(os.Stderr, "warning: remove %s: %v\n", path, err)
	}

	fmt.Println("==> Done. Off-box replicas on any peer boxes are untouched.")
	return nil
}

// removeSystemdTimer best-effort stops, disables, and deletes one unit's
// service/timer/enabled-symlink files. A unit that was never installed
// here (e.g. replicate, when no replication target was configured) means
// every step below is a harmless no-op, not an error.
func removeSystemdTimer(unit string) {
	exec.Command("systemctl", "disable", "--now", unit+".timer").Run()
	os.Remove(filepath.Join(systemdUnitDir, unit+".service"))
	os.Remove(filepath.Join(systemdUnitDir, unit+".timer"))
	os.Remove(filepath.Join(systemdTimersWantsDir, unit+".timer"))
}

// removeCronEntryFile is recreateCronEntryFile's inverse: drops any line
// containing marker and leaves everything else in the crontab spool file
// exactly as it was, matching the same never-touch-other-jobs guarantee.
// Removes the file entirely if nothing else was in it.
func removeCronEntryFile(path, marker string) error {
	existing, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("uninstall: read %s: %w", path, err)
	}

	var kept []string
	if len(existing) > 0 {
		for _, line := range strings.Split(strings.TrimRight(string(existing), "\n"), "\n") {
			if line == "" || strings.Contains(line, marker) {
				continue
			}
			kept = append(kept, line)
		}
	}

	if len(kept) == 0 {
		if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
			return fmt.Errorf("uninstall: remove %s: %w", path, err)
		}
		return nil
	}
	if err := os.WriteFile(path, []byte(strings.Join(kept, "\n")+"\n"), 0o600); err != nil {
		return fmt.Errorf("uninstall: write %s: %w", path, err)
	}
	return nil
}
