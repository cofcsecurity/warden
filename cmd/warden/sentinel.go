package main

import (
	"fmt"
	"time"

	"github.com/spf13/cobra"

	"warden/internal/audit"
	"warden/internal/autoban"
	"warden/internal/sentinel"
)

func sentinelCheckCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "sentinel-check",
		Short: "Verify the sentinel pair (systemd timer + cron entry) and respawn if needed",
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

	// Ban reconciliation piggybacks on sentinel-check's existing
	// "reassert desired state every pass" schedule, rather than adding a
	// third periodic invocation: reapply any active ban whose firewall
	// rule might have been flushed (a reboot, or red team running
	// iptables -F), and lift anything past its expiry.
	active, expired, err := autoban.Reconcile(autoban.NewStore(p.bannedIPsPath), autoban.IPTables{}, time.Now())
	if err != nil {
		return fmt.Errorf("sentinel-check: reconcile bans: %w", err)
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
	return nil
}
