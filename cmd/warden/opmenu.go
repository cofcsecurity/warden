package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"warden/internal/audit"
	"warden/internal/opmenu"
)

func opmenuCmd() *cobra.Command {
	return &cobra.Command{
		Use:    "opmenu",
		Short:  "Forced-command handler for the team key (never invoked directly)",
		Hidden: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runOpmenu()
		},
	}
}

// opmenuDenied are subcommands that make no sense over the team key.
var opmenuDenied = map[string]bool{"opmenu": true, "receive": true, "completion": true}

// runOpmenu is what the team key's command="sudo <path> opmenu" executes.
// The operator's request comes only from $SSH_ORIGINAL_COMMAND: anything
// typed after the host on the ssh command line. No command means a shell.
//
//	ssh -t netmgr@box              # root shell
//	ssh netmgr@box status          # one command
//	ssh netmgr@box restore /etc/ssh/sshd_config --apply
func runOpmenu() error {
	req := opmenu.Parse(os.Getenv("SSH_ORIGINAL_COMMAND"), os.Getenv("SSH_CLIENT"))

	var logFn func(string, map[string]any)
	if p, err := loadPaths(); err == nil {
		if log, err := audit.New(p.auditLogPath); err == nil {
			defer log.Close()
			logFn = func(action string, fields map[string]any) { _ = log.Log("opmenu", action, fields) }
		}
	}

	h := &opmenu.Handler{
		Run: func(args []string) error {
			root := newRootCmd()
			root.SetArgs(args)
			return root.Execute()
		},
		Allowed:   opmenuAllowed,
		ShellPath: "/bin/bash",
		Log:       logFn,
	}
	err := h.Handle(req)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
	}
	return err
}

func opmenuAllowed(name string) bool {
	if opmenuDenied[name] {
		return false
	}
	if name == "help" || name == "--help" || name == "-h" {
		return true
	}
	for _, c := range newRootCmd().Commands() {
		if c.Name() == name || c.HasAlias(name) {
			return true
		}
	}
	return false
}
