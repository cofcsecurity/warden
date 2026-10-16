package main

import (
	"fmt"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"warden/internal/audit"
)

// alertsCmd is pull-based rather than a broadcast (`wall` would just as
// happily tell red's shell it has been noticed): a teammate runs it in
// their own session and only that session sees it.
func alertsCmd() *cobra.Command {
	var follow bool
	cmd := &cobra.Command{
		Use:   "alerts",
		Short: "Show what Warden restored, quarantined, repaired and flagged",
		Long: `Prints the notable entries from the local log: files restored or
quarantined, access links repaired, things flagged for a human, bans and
locks (or what would have been banned or locked in flag mode). With
--follow it keeps printing new ones until Ctrl-C.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runAlerts(follow)
		},
	}
	cmd.Flags().BoolVarP(&follow, "follow", "f", false, "keep printing new alerts")
	return cmd
}

// notable reports whether a log entry belongs in alerts.
func notable(e audit.Entry) bool {
	switch e.Component {
	case "react":
		return true
	case "watch":
		switch e.Action {
		case "auto-restored", "quarantined", "flagged", "flagged-symlink", "flagged-unexpected", "read-failed":
			return true
		}
	case "sentinel":
		switch e.Action {
		case "recreated", "flagged", "repair-failed", "check-failed":
			return true
		}
	}
	return false
}

func runAlerts(follow bool) error {
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
		if notable(e) {
			printAlert(e)
			seen++
		}
	}
	if seen == 0 {
		fmt.Println("(no alerts yet)")
	}
	if !follow {
		return nil
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
			if notable(e) {
				printAlert(e)
			}
		}
		total = len(entries)
	}
}

func printAlert(e audit.Entry) {
	ts := e.Time.Local().Format("15:04:05")
	switch e.Component {
	case "watch":
		path, _ := e.Fields["path"].(string)
		fmt.Printf("[%s] %s %s\n", ts, e.Action, path)
		return
	case "sentinel":
		name, _ := e.Fields["registration"].(string)
		line := fmt.Sprintf("[%s] access %s: %s", ts, e.Action, name)
		if problems, ok := e.Fields["problems"].([]any); ok && len(problems) > 0 {
			var ps []string
			for _, p := range problems {
				ps = append(ps, fmt.Sprint(p))
			}
			line += " (" + strings.Join(ps, "; ") + ")"
		}
		if msg, ok := e.Fields["error"].(string); ok {
			line += ": " + msg
		}
		fmt.Println(line)
		return
	}
	switch e.Action {
	case "alert":
		switch source, _ := e.Fields["source"].(string); source {
		case "anomaly":
			printAnomalyAlert(ts, e)
			return
		}
		path, _ := e.Fields["path"].(string)
		if suspectIP, ok := e.Fields["suspect_ip"].(string); ok && suspectIP != "" {
			account, _ := e.Fields["account"].(string)
			banned, _ := e.Fields["autobanned"].(bool)
			bannedNote := "not banned"
			if banned {
				bannedNote = "BANNED"
			} else if would, _ := e.Fields["would_ban"].(string); would != "" {
				bannedNote = "flag mode: would ban"
			}
			fmt.Printf("[%s] ⚠ %s changed while %s had a root session as %q (%s)\n", ts, path, suspectIP, account, bannedNote)
		} else {
			evidence, _ := e.Fields["evidence"].(string)
			fmt.Printf("[%s] ⚠ %s changed, but couldn't attribute it to a specific outside IP (%s) — might want to check that\n", ts, path, evidence)
			printCandidateIPs(e)
		}
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
