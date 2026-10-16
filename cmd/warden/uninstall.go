package main

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"

	"warden/internal/accountlock"
	"warden/internal/fsutil"
)

// uninstallCmd removes everything `install` and sentinel set up. It is how a
// team undoes a bad setup; it asks for a typed "yes" (or --yes) and refuses
// on an armed box without --force.
func uninstallCmd() *cobra.Command {
	var force, assumeYes bool

	cmd := &cobra.Command{
		Use:   "uninstall",
		Short: "Remove Warden and everything it set up from this box",
		Long: `Stops every trigger first (so sentinel cannot put things back mid-way),
then removes the timers and path units, the cron entries, the sshd hooks
and drop-ins, the firewall allow rule, the sudoers rules, both access
accounts, the binary and its spares, and all local state. Copies already
on peer boxes are untouched.

Refuses on an armed box unless --force is given.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runUninstall(force, assumeYes)
		},
	}
	cmd.Flags().BoolVar(&force, "force", false, "remove even if the box is armed")
	cmd.Flags().BoolVar(&assumeYes, "yes", false, "skip the confirmation prompt")
	return cmd
}

func runUninstall(force, assumeYes bool) error {
	p, err := loadPaths()
	if err != nil {
		return err
	}
	armed, err := isArmed(p)
	if err != nil {
		return err
	}
	if armed && !force {
		return fmt.Errorf("uninstall: this box is armed; re-run with --force to remove Warden anyway")
	}
	if !assumeYes {
		fmt.Print("This removes Warden entirely from this box. Type 'yes' to confirm: ")
		answer, _ := bufio.NewReader(os.Stdin).ReadString('\n')
		if strings.TrimSpace(answer) != "yes" {
			return fmt.Errorf("uninstall: not confirmed, nothing removed")
		}
	}

	path, err := installPath()
	if err != nil {
		return err
	}
	name, err := binaryName()
	if err != nil {
		return err
	}
	accounts, err := accessAccounts()
	if err != nil {
		return err
	}
	warn := func(err error) {
		if err != nil {
			fmt.Fprintf(os.Stderr, "warning: %v\n", err)
		}
	}

	if err := os.MkdirAll(p.storeRoot, 0o700); err == nil {
		if release, err := fsutil.LockWait(filepath.Join(p.storeRoot, "operation.lock"), lockTimeout); err == nil {
			defer release()
		}
	}

	// Disarm first, so a watch pass already in flight cannot restore
	// /etc/passwd (and our accounts with it) after we remove them.
	_ = os.Remove(p.armedMarkerPath)

	fmt.Println("==> Stopping triggers")
	units := []string{name + sentinelSuffix}
	for _, suffix := range []string{watchSuffix, snapshotConfigSuffix, snapshotDataSuffix, scanSuffix, replicateSuffix} {
		units = append(units, name+suffix)
	}
	if cfg.BreakGlassUser != "" {
		units = append(units, cfg.BreakGlassUser+sentinelSuffix)
	}
	for _, u := range units {
		_, _ = runCommand("systemctl", "disable", "--now", u+".path", u+".timer")
	}
	if sentinelUnit, err := sentinelUnitName(); err == nil {
		warn(removeCronEntryFile(cronSpoolPath(), cronMarker(sentinelUnit)))
	}
	if cfg.BreakGlassUser != "" {
		warn(removeIfExists("/etc/cron.d/" + cfg.BreakGlassUser))
	}

	fmt.Println("==> Removing units and hooks")
	for _, u := range units {
		removeSystemdTimer(u)
		warn(removeIfExists(filepath.Join(systemdUnitDir, u+".path")))
		warn(removeIfExists(filepath.Join(systemdPathsWantsDir, u+".path")))
	}
	if unit := sshdUnit(); unit != "" {
		warn(removeIfExists(filepath.Join(systemdUnitDir, unit+".service.d", name+".conf")))
	}
	warn(runSystemctl("daemon-reload"))

	fmt.Println("==> Removing firewall allow rules")
	for _, rule := range firewallRules() {
		for {
			if _, err := runCommand("iptables", append([]string{"-w", "-D", "INPUT"}, rule...)...); err != nil {
				break
			}
		}
	}

	fmt.Println("==> Removing access accounts, keys, sudoers rules and sshd drop-ins")
	for _, a := range accounts {
		warn(removeIfExists(a.SSHDDropIn))
		warn(removeIfExists(a.Sudoers))
		if out, err := runCommand("userdel", "-f", a.User); err != nil {
			warn(fmt.Errorf("userdel %s: %v: %s", a.User, err, out))
		}
		warn(os.RemoveAll(a.Home))
		warn(os.RemoveAll(filepath.Dir(a.KeysPath)))
	}
	warn(reloadSSHD())

	// Account locks are recorded in the state directory, which is about
	// to go; lift them first so no account stays locked with no record.
	fmt.Println("==> Lifting any active account locks")
	if locks, err := accountlock.NewStore(p.accountLocksPath).Load(); err != nil {
		warn(err)
	} else {
		sys := accountlock.OSAccounts{NologinShell: nologinShellPath()}
		for _, l := range locks {
			warn(sys.Unlock(l.User, l.PreviousShell))
		}
	}

	fmt.Println("==> Removing local state, spares and peer copies held here")
	warn(os.RemoveAll(p.mirrorDir))
	warn(os.RemoveAll(p.peerRoot))
	warn(os.RemoveAll(p.dataDir))

	fmt.Println("==> Removing installed binary:", path)
	warn(removeIfExists(path))

	fmt.Println("==> Done. Copies on peer boxes are untouched.")
	return nil
}

func removeIfExists(path string) error {
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}

// removeSystemdTimer best-effort stops, disables, and deletes one unit's
// service/timer/enabled-symlink files. A unit that was never installed
// here (e.g. replicate, when no replication target was configured) means
// every step below is a harmless no-op, not an error.
func removeSystemdTimer(unit string) {
	_, _ = runCommand("systemctl", "disable", "--now", unit+".timer")
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
