package main

import (
	"errors"
	"fmt"
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
		Short: "Verify every registration and timer, respawn what's missing, and check on peers",
		RunE: func(cmd *cobra.Command, args []string) error {
			return runSentinelCheck()
		},
	}
}

func runSentinelCheck() error {
	p, err := loadPaths()
	if err != nil {
		return err
	}

	log, err := audit.New(p.auditLogPath)
	if err != nil {
		return err
	}
	defer log.Close()

	regs, err := buildRegistrations()
	if err != nil {
		return err
	}

	s := sentinel.New(regs, log)
	res, err := s.Run()
	if err != nil {
		return err
	}

	if err := log.Log("sentinel", "pass", map[string]any{
		"ok":        len(res.OK),
		"recreated": len(res.Recreated),
	}); err != nil {
		return err
	}

	if len(res.Recreated) > 0 {
		fmt.Printf("recreated: %v\n", res.Recreated)
	}

	// Reconcile errors below are collected rather than returned straight
	// away: each pass keeps going past a single failure internally (see
	// autoban.Reconcile), so ending sentinel-check on the first error
	// would undo that by skipping the other reconcile entirely.
	var reconcileErrs []error

	// Ban reconciliation piggybacks on sentinel-check's existing
	// "reassert desired state every pass" schedule, rather than adding a
	// third periodic invocation: reapply any active ban whose firewall
	// rule might have been flushed (a reboot, or red team running
	// iptables -F), and lift anything past its expiry.
	active, expired, err := autoban.Reconcile(autoban.NewStore(p.bannedIPsPath), autoban.IPTables{}, time.Now())
	if err != nil {
		reconcileErrs = append(reconcileErrs, fmt.Errorf("sentinel-check: reconcile bans: %w", err))
	}
	if len(expired) > 0 {
		if err := log.Log("react", "ban-expired", map[string]any{"ips": expired}); err != nil {
			return err
		}
		fmt.Printf("ban(s) expired: %v\n", expired)
	}
	if len(active) > 0 {
		fmt.Printf("active ban(s) reasserted: %v\n", active)
	}

	// Reassert active account restrictions and lift successfully expired locks.

	lockedAccounts, expiredLocks, err := accountlock.Reconcile(
		accountlock.NewStore(p.accountLocksPath),
		accountlock.OSAccounts{NologinShell: nologinShellPath()},
		time.Now(),
	)
	if err != nil {
		reconcileErrs = append(reconcileErrs, fmt.Errorf("sentinel-check: reconcile account locks: %w", err))
	}
	if len(expiredLocks) > 0 {
		if err := log.Log("react", "lock-expired", map[string]any{"users": expiredLocks}); err != nil {
			return err
		}
		fmt.Printf("account lock(s) expired: %v\n", expiredLocks)
	}
	if len(lockedAccounts) > 0 {
		fmt.Printf("active account lock(s): %v\n", lockedAccounts)
	}

	// The dead-man's switch for *other* boxes, on the same schedule and
	// for the same reason as the reconciles above: this box is the only
	// place a peer's silence can be noticed, since a box that has gone
	// dark by definition isn't running anything that could report it.
	if err := checkPeerHeartbeats(p, log, time.Now()); err != nil {
		reconcileErrs = append(reconcileErrs, fmt.Errorf("sentinel-check: check peer heartbeats: %w", err))
	}

	return errors.Join(reconcileErrs...)
}
