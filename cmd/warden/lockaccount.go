package main

import (
	"fmt"
	"time"

	"github.com/spf13/cobra"

	"warden/internal/accountlock"
	"warden/internal/audit"
)

// lockAccountCmd/unlockAccountCmd are the manual override for scan.go's
// automatic reaction, the same relationship ban.go/unban.go have to
// react.go's automatic IP ban: a human calling this directly, having
// already decided an account deserves it (or that a prior auto-lock was
// wrong).
func lockAccountCmd() *cobra.Command {
	var duration time.Duration
	var reason string
	var force bool

	cmd := &cobra.Command{
		Use:   "lock-account <user>",
		Short: "Manually lock a local account and kill its sessions",
		Long: `Disables password auth and interactive shell access for user, and
best-effort kills its currently running sessions. Refuses to lock root,
the opmenu account itself (no override — either would be self-inflicted
damage), an account that isn't genuinely local (likely Active Directory/
directory-backed — a local lock has no effect on one of those), or an
account on the configured SAFE_ACCOUNTS list (override with --force).`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runLockAccount(args[0], reason, duration, force)
		},
	}
	cmd.Flags().DurationVar(&duration, "duration", accountLockDuration, "lock duration (0 means indefinite; positive durations expire)")
	cmd.Flags().StringVar(&reason, "reason", "manual lock", "short note recorded alongside the lock in audit.log")
	cmd.Flags().BoolVar(&force, "force", false, "lock even if the account is on the configured SAFE_ACCOUNTS list")
	return cmd
}

func unlockAccountCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "unlock-account <user>",
		Short: "Lift an account lock immediately, e.g. to undo a false positive",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runUnlockAccount(args[0])
		},
	}
}

func runLockAccount(user, reason string, duration time.Duration, force bool) error {
	ok, why, err := canLockAccount(user, force)
	if err != nil {
		return err
	}
	if !ok {
		return fmt.Errorf("lock-account: refusing to lock %s: %s", user, why)
	}

	p, err := loadPaths()
	if err != nil {
		return err
	}
	sys := accountlock.OSAccounts{NologinShell: nologinShellPath()}
	store := accountlock.NewStore(p.accountLocksPath)
	if err := accountlock.Add(store, sys, user, reason, duration, time.Now()); err != nil {
		return err
	}
	_ = sys.KillSessions(user)

	log, err := audit.New(p.auditLogPath)
	if err != nil {
		return err
	}
	defer log.Close()
	if err := log.Log("react", "manual-lock", map[string]any{"user": user, "reason": reason, "duration": duration.String()}); err != nil {
		return err
	}

	if duration == 0 {
		fmt.Printf("locked %s indefinitely: %s\n", user, reason)
	} else {
		fmt.Printf("locked %s for %s: %s\n", user, duration, reason)
	}
	return nil
}

func runUnlockAccount(user string) error {
	p, err := loadPaths()
	if err != nil {
		return err
	}
	sys := accountlock.OSAccounts{NologinShell: nologinShellPath()}
	store := accountlock.NewStore(p.accountLocksPath)
	if err := accountlock.Remove(store, sys, user); err != nil {
		return err
	}

	log, err := audit.New(p.auditLogPath)
	if err != nil {
		return err
	}
	defer log.Close()
	if err := log.Log("react", "manual-unlock", map[string]any{"user": user}); err != nil {
		return err
	}

	fmt.Printf("unlocked %s\n", user)
	return nil
}
