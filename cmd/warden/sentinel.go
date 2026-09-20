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
	return nil
}
