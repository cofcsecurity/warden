package main

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"

	"warden/internal/accountlock"
)

// uninstallCmd reverses everything install.sh set up, as a way back to a
// clean box if setup goes wrong — a full transactional install (roll back
// automatically on any failure partway through) would need every step in
// install.sh to be independently reversible and the two scripts kept in
// exact lockstep forever; this is the more honest version of that: one
// explicit command that undoes it all, callable either after a failed
// setup or any time before arming.
//
// This is one of the most dangerous things this binary can do — it's how
// a team member undoes a bad setup, but it's also exactly what red team
// would run first if they ever got root through some completely
// unrelated route (a vulnerable service, say) rather than through
// opmenu: a single command that strips out every persistence mechanism
// Warden has, no opmenu second factor required, since this runs locally
// as root already. Gated the same way accept.go is (a valid TOTP code or
// the static secret — see verifySecondFactor), so holding root alone is
// never enough, plus a typed confirmation on top of that so a leaked or
// shoulder-surfed code can't wipe the box unattended. Refuses once armed
// unless --force is also passed — see the Long help text for why that
// line is drawn at arm, not at install.
func uninstallCmd() *cobra.Command {
	var force, assumeYes bool

	cmd := &cobra.Command{
		Use:   "uninstall <code>",
		Short: "Remove everything install.sh set up on this box",
		Long: `Reverses install.sh: stops and deletes every systemd timer (watch,
sentinel, both snapshot tiers, replicate), the cron fallback entry, the
sudoers rule, the dedicated access-layer account, the installed binary
and its hidden spare copy, and all local state under /var/lib/<name>
(manifests, the backup store, the audit log, the static secret). Off-box
replicas already pushed to a peer box are never touched — recovering
from one later still works the same way docs/DEPLOYMENT.md describes.

Requires a current TOTP code or the static secret (see rotate-secret) —
the same proof of authorization restore/shell/accept require — since
otherwise anyone who gets a root shell through any route at all, not
just opmenu, could use this to strip every defense Warden has in one
command. Also asks for a typed 'yes' before doing anything (skip with
--yes for scripted use, but the code is still checked either way).

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
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runUninstall(args[0], force, assumeYes)
		},
	}
	cmd.Flags().BoolVar(&force, "force", false, "remove even if the box is currently armed")
	cmd.Flags().BoolVar(&assumeYes, "yes", false, "skip the interactive confirmation prompt (the code is still required)")
	return cmd
}

func runUninstall(code string, force, assumeYes bool) error {
	ok, err := verifySecondFactor(code)
	if err != nil {
		return fmt.Errorf("uninstall: %w", err)
	}
	if !ok {
		return fmt.Errorf("uninstall: invalid or expired code")
	}

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

	if !assumeYes {
		fmt.Print("This removes Warden entirely from this box. Type 'yes' to confirm: ")
		reader := bufio.NewReader(os.Stdin)
		answer, _ := reader.ReadString('\n')
		if strings.TrimSpace(answer) != "yes" {
			return fmt.Errorf("uninstall: not confirmed, nothing removed")
		}
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
	for _, suffix := range []string{"-watch", "-sentinel", "-snap-cfg", "-snap-data", "-replicate", "-scan"} {
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

	// Must happen before p.dataDir is removed below: accountLocksPath
	// lives inside it, and it's the only record of which accounts are
	// currently locked and what shell to restore. Removing it first
	// would leave any currently-locked account locked out forever, with
	// nothing left anywhere recording that it happened at all.
	fmt.Println("==> Lifting any active account locks")
	lockStore := accountlock.NewStore(p.accountLocksPath)
	if locks, err := lockStore.Load(); err != nil {
		fmt.Fprintf(os.Stderr, "warning: read %s: %v\n", p.accountLocksPath, err)
	} else {
		sys := accountlock.OSAccounts{NologinShell: nologinShellPath()}
		for _, l := range locks {
			if err := sys.Unlock(l.User, l.PreviousShell); err != nil {
				fmt.Fprintf(os.Stderr, "warning: unlock %s: %v\n", l.User, err)
			}
		}
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
	// Worth saying plainly: the peers are about to start reporting this
	// box as silent, and someone reading `warden fleet` there shouldn't
	// spend time investigating a box the team took down on purpose.
	if buildReplicateTargets != "" {
		fmt.Println("    Peers will report this box as silent within the hour — that's the")
		fmt.Println("    heartbeat noticing an uninstall, not a separate problem.")
	}
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
