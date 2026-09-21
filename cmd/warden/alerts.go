package main

import (
	"fmt"
	"strings"
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
		switch source, _ := e.Fields["source"].(string); source {
		case "anomaly":
			printAnomalyAlert(ts, e)
			return
		case "heartbeat":
			printHeartbeatAlert(ts, e)
			return
		}
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
			printCandidateIPs(e)
		}
	case "peer-returned":
		peer, _ := e.Fields["peer"].(string)
		fmt.Printf("[%s] %s is reporting again\n", ts, peer)
	case "manual-ban":
		ip, _ := e.Fields["ip"].(string)
		reason, _ := e.Fields["reason"].(string)
		fmt.Printf("[%s] manually banned %s: %s\n", ts, ip, reason)
	case "manual-unban":
		ip, _ := e.Fields["ip"].(string)
		fmt.Printf("[%s] manually unbanned %s\n", ts, ip)
	case "manual-lock":
		user, _ := e.Fields["user"].(string)
		reason, _ := e.Fields["reason"].(string)
		fmt.Printf("[%s] manually locked account %s: %s\n", ts, user, reason)
	case "manual-unlock":
		user, _ := e.Fields["user"].(string)
		fmt.Printf("[%s] manually unlocked account %s\n", ts, user)
	}
}

// printAnomalyAlert renders a scan.go finding — a distinct shape from the
// guarded-file-change alert above (no single "path", possibly an account
// lock in play alongside or instead of an IP ban).
func printAnomalyAlert(ts string, e audit.Entry) {
	check, _ := e.Fields["check"].(string)
	desc, _ := e.Fields["description"].(string)
	fmt.Printf("[%s] ⚠ [%s] %s\n", ts, check, desc)

	if culprit, ok := e.Fields["culprit"].(string); ok && culprit != "" {
		locked, _ := e.Fields["locked_account"].(bool)
		status := "not locked"
		if locked {
			status = "LOCKED"
		}
		fmt.Printf("           account: %s (%s)\n", culprit, status)
		if reason, ok := e.Fields["lock_skipped_reason"].(string); ok && reason != "" {
			fmt.Printf("           %s\n", reason)
		}
	}

	if suspectIP, ok := e.Fields["suspect_ip"].(string); ok && suspectIP != "" {
		banned, _ := e.Fields["autobanned"].(bool)
		bannedNote := "not banned"
		if banned {
			bannedNote = "BANNED"
		}
		fmt.Printf("           source IP: %s (%s)\n", suspectIP, bannedNote)
	} else {
		printCandidateIPs(e)
	}
}

// printHeartbeatAlert renders a peer that has stopped reporting. Worth a
// distinct shape from the other alerts: nothing happened *on this box*,
// and the box it's about is exactly the one that can't tell anyone
// itself.
func printHeartbeatAlert(ts string, e audit.Entry) {
	peer, _ := e.Fields["peer"].(string)
	desc, _ := e.Fields["description"].(string)
	fmt.Printf("[%s] ⚠ [heartbeat] %s\n", ts, desc)
	if lastSeen, ok := e.Fields["last_seen"].(string); ok && lastSeen != "" {
		fmt.Printf("           %s last reported at %s — 'warden fleet' for the full picture\n", peer, lastSeen)
	}
}

// printCandidateIPs renders the shortlist behind an "ambiguous, not
// banned" alert (see react.go's attributeChange). Nothing was banned
// automatically, so the whole value of the alert is handing an operator
// the addresses to look at — and a second decoy session is all it takes
// for an attacker to land in this branch on purpose.
func printCandidateIPs(e audit.Entry) {
	raw, ok := e.Fields["candidate_ips"].([]any)
	if !ok || len(raw) == 0 {
		return
	}
	ips := make([]string, 0, len(raw))
	for _, v := range raw {
		if ip, ok := v.(string); ok {
			ips = append(ips, ip)
		}
	}
	if len(ips) == 0 {
		return
	}
	fmt.Printf("           candidate IPs (none banned automatically): %s\n", strings.Join(ips, ", "))
	fmt.Printf("           → 'warden ban <ip>' if you can tell which of these is red team\n")
}
