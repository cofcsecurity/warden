package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
	"warden/internal/fsutil"

	"github.com/spf13/cobra"

	"warden/internal/audit"
	"warden/internal/manifest"
	"warden/internal/opmenu"
	"warden/internal/restore"
	"warden/internal/store"
)

func opmenuCmd() *cobra.Command {
	return &cobra.Command{
		Use:    "opmenu",
		Short:  "Forced-command handler for the access layer (never invoked directly)",
		Hidden: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runOpmenu()
		},
	}
}

// runOpmenu is what authorized_keys' command="/usr/local/sbin/warden opmenu"
// actually executes. It never trusts args: the operator's real request
// comes only through $SSH_ORIGINAL_COMMAND, since that's the one thing a
// forced-command entry can't let the client override.
func runOpmenu() error {
	p, err := loadPaths()
	if err != nil {
		return err
	}

	log, err := audit.New(p.auditLogPath)
	if err != nil {
		return err
	}
	defer log.Close()

	req, err := parseOpmenuRequest(os.Getenv("SSH_ORIGINAL_COMMAND"), os.Getenv("SSH_CLIENT"))
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return err
	}

	h := opmenu.New(
		buildTOTPSecret,
		p.staticSecretPath,
		p.spentTOTPPath,
		func() (string, error) { return runStatus(p) },
		func(target string, args []string) (string, error) { return runOpmenuRestore(p, target, args) },
		"/bin/bash",
		log,
	)

	out, err := h.Handle(req)
	if out != "" {
		fmt.Println(out)
	}
	return err
}

// parseOpmenuRequest expects "<command> [totp-code] [args...]", e.g.
// "status", "restore 123456 nginx", "restore 123456 nginx apply", "shell
// 123456".
func parseOpmenuRequest(raw, sshClient string) (opmenu.Request, error) {
	fields := strings.Fields(raw)
	if len(fields) == 0 {
		return opmenu.Request{}, fmt.Errorf("opmenu: empty command")
	}

	sourceIP := ""
	if clientFields := strings.Fields(sshClient); len(clientFields) > 0 {
		sourceIP = clientFields[0] // SSH_CLIENT is "<ip> <port> <port>"
	}

	req := opmenu.Request{
		Command:  opmenu.Command(fields[0]),
		SourceIP: sourceIP,
	}

	rest := fields[1:]
	if req.Command == opmenu.CommandRestore || req.Command == opmenu.CommandShell {
		if len(rest) == 0 {
			return opmenu.Request{}, fmt.Errorf("opmenu: %s requires a TOTP code", req.Command)
		}
		req.TOTPCode, rest = rest[0], rest[1:]
	}
	req.Args = rest

	return req, nil
}

// runStatus reports read-only state: manifest generation, last snapshot
// time, and the last recorded pass of watch and sentinel-check. It's the
// one opmenu command that never requires a TOTP code, so it stays cheap
// and side-effect-free.
func runStatus(p paths) (string, error) {
	m, err := manifest.New(p.configManifestPath)
	if err != nil {
		return "", err
	}

	entries, err := audit.Read(p.auditLogPath)
	if err != nil {
		return "", err
	}
	last := audit.LastByComponent(entries)

	armed, err := isArmed(p)
	if err != nil {
		return "", err
	}

	var b strings.Builder
	if armed {
		fmt.Fprintf(&b, "armed: yes (auto-restore is on)\n")
	} else {
		fmt.Fprintf(&b, "armed: NO — auto-restore is off, drift is only flagged. run 'arm' once hardening is done.\n")
	}
	if _, err := os.Stat(p.staticSecretPath); err == nil {
		fmt.Fprintf(&b, "static second factor: set (in addition to TOTP — run 'rotate-secret' to change it)\n")
	} else {
		fmt.Fprintf(&b, "static second factor: not set (TOTP only — run 'rotate-secret' if phones/authenticator apps aren't usable here)\n")
	}
	fmt.Fprintf(&b, "manifest generation: %d\n", m.Generation)
	if m.CreatedAt.IsZero() {
		fmt.Fprintf(&b, "last snapshot: none\n")
	} else {
		fmt.Fprintf(&b, "last snapshot: %s\n", m.CreatedAt.Format(time.RFC3339))
	}
	// Every periodic component reports here, not just watch and
	// sentinel: each one is a whole capability (drift response, anomaly
	// detection, off-box evidence), and a timer that silently stopped
	// firing looks exactly like a quiet box unless status says when that
	// component last ran.
	fmt.Fprintf(&b, "last watch pass: %s\n", summarizeEntry(last["watch"]))
	fmt.Fprintf(&b, "last sentinel check: %s\n", summarizeEntry(last["sentinel"]))
	fmt.Fprintf(&b, "last anomaly scan: %s\n", summarizeEntry(last["scan"]))
	if buildReplicateTargets == "" {
		fmt.Fprintf(&b, "last replication: not configured on this build\n")
	} else {
		fmt.Fprintf(&b, "last replication: %s\n", summarizeEntry(last["replicate"]))
	}

	fmt.Fprintf(&b, "backup health: %s\n", backupHealthSummary(p))
	if q, err := loadReloadQueue(p); err != nil {
		fmt.Fprintf(&b, "pending reloads: %v\n", err)
	} else {
		fmt.Fprintf(&b, "pending reloads: %d\n", len(q.Units))
	}
	local := store.Open(p.storeRoot)
	for _, tier := range []snapshotTier{tierConfig, tierData} {
		m, err := manifest.New(p.manifestPathForTier(tier))
		if err != nil {
			fmt.Fprintf(&b, "%s snapshot: invalid: %v\n", tier, err)
			continue
		}
		missing := 0
		for _, rec := range m.Records {
			if !local.Has(rec.Hash) {
				missing++
			}
		}
		fmt.Fprintf(&b, "%s snapshot: generation %d, unavailable local objects=%d\n", tier, m.Generation, missing)
	}
	return strings.TrimRight(b.String(), "\n"), nil
}

func summarizeEntry(e audit.Entry) string {
	if e.Time.IsZero() {
		return "none recorded"
	}
	return fmt.Sprintf("%s (%s) %v", e.Time.Format(time.RFC3339), e.Action, e.Fields)
}

// runOpmenuRestore mirrors `warden restore`'s dry-run-by-default behavior:
// it only applies when the caller explicitly appends "apply" as the last
// argument, since this path is reached over SSH with a live TOTP code
// already spent, not a two-step CLI flag a human can reconsider.
func runOpmenuRestore(p paths, target string, args []string) (string, error) {
	apply := len(args) > 0 && args[0] == "apply"
	if apply {
		release, err := fsutil.Lock(filepath.Join(p.storeRoot, "operation.lock"))
		if err != nil {
			return "", err
		}
		defer release()
	}

	m, err := loadSnapshot(p, "")
	if err != nil {
		return "", err
	}

	entries, err := restore.Plan(m, target)
	if err != nil {
		return "", err
	}

	lines := planLines(entries)

	if !apply {
		lines = append(lines, "dry run: append 'apply' to actually restore")
		return strings.Join(lines, "\n"), nil
	}

	log, err := audit.New(p.auditLogPath)
	if err != nil {
		return "", err
	}
	defer log.Close()

	applyLines, err := applyPlan(p, entries, log)
	lines = append(lines, applyLines...)
	return strings.Join(lines, "\n"), err
}
