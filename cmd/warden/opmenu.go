package main

import (
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"warden/internal/audit"
	"warden/internal/manifest"
	"warden/internal/opmenu"
	"warden/internal/restore"
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
	log, err := audit.New(auditLogPath)
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
		runStatus,
		runOpmenuRestore,
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
func runStatus() (string, error) {
	m, err := manifest.New(manifestPath)
	if err != nil {
		return "", err
	}

	entries, err := audit.Read(auditLogPath)
	if err != nil {
		return "", err
	}
	last := audit.LastByComponent(entries)

	var b strings.Builder
	fmt.Fprintf(&b, "manifest generation: %d\n", m.Generation)
	if m.CreatedAt.IsZero() {
		fmt.Fprintf(&b, "last snapshot: none\n")
	} else {
		fmt.Fprintf(&b, "last snapshot: %s\n", m.CreatedAt.Format(time.RFC3339))
	}
	fmt.Fprintf(&b, "last watch pass: %s\n", summarizeEntry(last["watch"]))
	fmt.Fprintf(&b, "last sentinel check: %s\n", summarizeEntry(last["sentinel"]))

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
func runOpmenuRestore(target string, args []string) (string, error) {
	apply := len(args) > 0 && args[0] == "apply"

	m, err := manifest.New(manifestPath)
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

	log, err := audit.New(auditLogPath)
	if err != nil {
		return "", err
	}
	defer log.Close()

	applyLines, err := applyPlan(entries, log)
	lines = append(lines, applyLines...)
	return strings.Join(lines, "\n"), err
}
