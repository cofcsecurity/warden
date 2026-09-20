package main

import (
	"fmt"

	"github.com/spf13/cobra"

	"warden/internal/audit"
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
	log, err := audit.New(auditLogPath)
	if err != nil {
		return err
	}
	defer log.Close()

	// TODO: build the real registrations list:
	//   - authorized_keys entry present (delegate to manifest/watch logic
	//     rather than duplicating the check here)
	//   - systemd timer unit file present
	//   - crontab entry present
	// Read the unit/crontab files directly rather than shelling out to
	// systemctl/crontab, per docs/DESIGN.md.
	regs := []sentinel.Registration{}

	s := sentinel.New(regs, log)
	res, err := s.Run()
	if err != nil {
		return err
	}

	if len(res.Recreated) > 0 {
		fmt.Printf("recreated: %v\n", res.Recreated)
	}
	return nil
}
