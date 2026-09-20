package main

import (
	"fmt"
	"time"

	"github.com/spf13/cobra"

	"warden/internal/audit"
	"warden/internal/autoban"
)

// banCmd/unbanCmd are the manual override for autoban's automatic
// reaction (react.go): a human calling this directly, having already
// decided an IP deserves it (or that a prior auto-ban was wrong).
func banCmd() *cobra.Command {
	var duration time.Duration
	var reason string

	cmd := &cobra.Command{
		Use:   "ban <ip>",
		Short: "Manually block an IP at the firewall for a limited time",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runBan(args[0], reason, duration)
		},
	}
	cmd.Flags().DurationVar(&duration, "duration", autobanDuration, "how long the ban lasts before sentinel-check's Reconcile lifts it")
	cmd.Flags().StringVar(&reason, "reason", "manual ban", "short note recorded alongside the ban in audit.log")
	return cmd
}

func unbanCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "unban <ip>",
		Short: "Lift a ban immediately, e.g. to undo a false positive",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runUnban(args[0])
		},
	}
}

func runBan(ip, reason string, duration time.Duration) error {
	p, err := loadPaths()
	if err != nil {
		return err
	}
	store := autoban.NewStore(p.bannedIPsPath)
	if err := autoban.Add(store, autoban.IPTables{}, ip, reason, duration, time.Now()); err != nil {
		return err
	}

	log, err := audit.New(p.auditLogPath)
	if err != nil {
		return err
	}
	defer log.Close()
	if err := log.Log("react", "manual-ban", map[string]any{"ip": ip, "reason": reason, "duration": duration.String()}); err != nil {
		return err
	}

	fmt.Printf("banned %s for %s: %s\n", ip, duration, reason)
	return nil
}

func runUnban(ip string) error {
	p, err := loadPaths()
	if err != nil {
		return err
	}
	store := autoban.NewStore(p.bannedIPsPath)
	if err := autoban.Remove(store, autoban.IPTables{}, ip); err != nil {
		return err
	}

	log, err := audit.New(p.auditLogPath)
	if err != nil {
		return err
	}
	defer log.Close()
	if err := log.Log("react", "manual-unban", map[string]any{"ip": ip}); err != nil {
		return err
	}

	fmt.Printf("unbanned %s\n", ip)
	return nil
}
