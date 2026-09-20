package main

import (
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"warden/internal/audit"
	"warden/internal/opmenu"
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
// "status", "restore 123456 nginx", "shell 123456".
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

func runStatus() (string, error) {
	// TODO: report manifest generation, last snapshot time, last watch
	// pass result, sentinel registration state.
	return "warden: status not yet implemented", nil
}

func runOpmenuRestore(target string, args []string) (string, error) {
	// TODO: call restore.Plan/Apply the same way `warden restore` does,
	// defaulting to dry-run unless args explicitly requests --apply.
	return "", fmt.Errorf("opmenu: restore not yet implemented")
}
