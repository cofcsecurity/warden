package main

import (
	"errors"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/spf13/cobra"

	"warden/internal/accountlock"
	"warden/internal/audit"
	"warden/internal/autoban"
	"warden/internal/sentinel"
)

func sentinelCheckCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "sentinel-check",
		Short: "Check every link of the access chain and every trigger, and repair what is broken",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			p, err := loadPaths()
			if err != nil {
				return err
			}
			return runSentinelCheck(p, os.Stdout)
		},
	}
}

// repairAccess runs one sentinel pass after a config change, so new keys,
// peers and units take effect at once rather than at the next tick.
// A var so tests of the commands that call it never touch the real box.
// It prints nothing: callers such as `pair accept` print output that is fed
// to another command.
var repairAccess = func(p paths) error {
	return runSentinelCheck(p, io.Discard)
}

func runSentinelCheck(p paths, w io.Writer) error {
	log, err := audit.New(p.auditLogPath)
	if err != nil {
		return err
	}
	defer log.Close()

	regs, err := buildRegistrations(p)
	if err != nil {
		return err
	}

	res, runErr := sentinel.New(regs, log).Run()
	if err := log.Log("sentinel", "pass", map[string]any{
		"ok":        len(res.OK),
		"recreated": len(res.Recreated),
		"flagged":   len(res.Flagged),
		"failed":    runErr != nil,
	}); err != nil {
		return err
	}
	if len(res.Recreated) > 0 {
		fmt.Fprintf(w, "repaired: %v\n", res.Recreated)
	}
	if len(res.Flagged) > 0 {
		fmt.Fprintf(w, "needs a human: %v (see 'warden alerts')\n", res.Flagged)
	}

	errs := []error{runErr}

	// Bans are live firewall rules; reassert them every pass in case they
	// were flushed, and lift any that expired.
	active, expired, err := autoban.Reconcile(autoban.NewStore(p.bannedIPsPath), autoban.IPTables{}, time.Now())
	if err != nil {
		errs = append(errs, fmt.Errorf("sentinel-check: reconcile bans: %w", err))
	}
	if len(expired) > 0 {
		_ = log.Log("react", "ban-expired", map[string]any{"ips": expired})
		fmt.Fprintf(w, "ban(s) expired: %v\n", expired)
	}
	if len(active) > 0 {
		fmt.Fprintf(w, "active ban(s) reasserted: %v\n", active)
	}

	lockedAccounts, expiredLocks, err := accountlock.Reconcile(
		accountlock.NewStore(p.accountLocksPath),
		accountlock.OSAccounts{NologinShell: nologinShellPath()},
		time.Now(),
	)
	if err != nil {
		errs = append(errs, fmt.Errorf("sentinel-check: reconcile account locks: %w", err))
	}
	if len(expiredLocks) > 0 {
		_ = log.Log("react", "lock-expired", map[string]any{"users": expiredLocks})
		fmt.Fprintf(w, "account lock(s) expired: %v\n", expiredLocks)
	}
	if len(lockedAccounts) > 0 {
		fmt.Fprintf(w, "active account lock(s): %v\n", lockedAccounts)
	}
	return errors.Join(errs...)
}
