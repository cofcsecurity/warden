package main

import (
	"fmt"
	"time"

	"github.com/spf13/cobra"

	"warden/internal/audit"
)

// alertsCmd is deliberately opt-in and pull-based rather than a broadcast
// to every session on the box (e.g. via `wall`): a system-wide broadcast
// would just as happily reach a shell red team has on the box through some
// other route, handing them free confirmation that they've been noticed.
// Instead, a teammate who wants to watch for trouble opens their own
// sidecar shell (over opmenu's TOTP-gated `shell`) and runs this there —
// only that session ever sees it.
func alertsCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "alerts",
		Short: "Tail guarded-path alerts in this shell only (run in a sidecar session)",
		Long: `Polls the audit log for react's alert/ban entries — someone touching a
guarded (ConfirmFirst) path, and whatever Warden could or couldn't
attribute that to — and prints them here as they happen. Ctrl-C to stop.

This is opt-in and local to whoever runs it, on purpose: it never
broadcasts to every session on the box the way 'wall' would, since that
would just as readily tip off an attacker who has some other shell on the
box that they've been noticed.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runAlerts()
		},
	}
}

func runAlerts() error {
	p, err := loadPaths()
	if err != nil {
		return err
	}

	entries, err := audit.Read(p.auditLogPath)
	if err != nil {
		return err
	}
	seen := 0
	for _, e := range entries {
		if e.Component == "react" {
			printAlert(e)
			seen++
		}
	}
	if seen == 0 {
		fmt.Println("(no alerts yet — watching for new ones)")
	}
	total := len(entries)

	for {
		time.Sleep(2 * time.Second)

		entries, err := audit.Read(p.auditLogPath)
		if err != nil {
			return err
		}
		if len(entries) <= total {
			continue
		}
		for _, e := range entries[total:] {
			if e.Component == "react" {
				printAlert(e)
			}
		}
		total = len(entries)
	}
}

func printAlert(e audit.Entry) {
	ts := e.Time.Local().Format("15:04:05")
	switch e.Action {
	case "alert":
		path, _ := e.Fields["path"].(string)
		if suspectIP, ok := e.Fields["suspect_ip"].(string); ok && suspectIP != "" {
			account, _ := e.Fields["account"].(string)
			banned, _ := e.Fields["autobanned"].(bool)
			bannedNote := "not banned"
			if banned {
				bannedNote = "BANNED"
			}
			fmt.Printf("[%s] ⚠ someone used account %q from %s to touch %s (%s)\n", ts, account, suspectIP, path, bannedNote)
		} else {
			evidence, _ := e.Fields["evidence"].(string)
			fmt.Printf("[%s] ⚠ %s changed, but couldn't attribute it to a specific outside IP (%s) — might want to check that\n", ts, path, evidence)
		}
	case "manual-ban":
		ip, _ := e.Fields["ip"].(string)
		reason, _ := e.Fields["reason"].(string)
		fmt.Printf("[%s] manually banned %s: %s\n", ts, ip, reason)
	case "manual-unban":
		ip, _ := e.Fields["ip"].(string)
		fmt.Printf("[%s] manually unbanned %s\n", ts, ip)
	}
}
