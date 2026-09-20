// Warden is a companion tool to seer: resilient, audited persistence and
// automatic backup/restore for a host under active attack in a CCDC-style
// competition. See docs/DESIGN.md for the full design.
package main

import (
	"log/slog"
	"os"

	"github.com/spf13/cobra"
)

// Build-time configuration, set via -ldflags -X main.<field>=<value>.
// These stay empty in a dev build; a real deploy build supplies all of
// them.
var (
	buildTeamPubKey   string
	buildTeamFromIP   string
	buildTOTPSecret   string
	buildReplicateURL string
)

func main() {
	var logLevel = new(slog.LevelVar)
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: logLevel}))
	slog.SetDefault(logger)

	var verbose bool

	root := &cobra.Command{
		Use:   "warden",
		Short: "Warden provides resilient persistence and backup/restore for a defended host",
		PersistentPreRun: func(cmd *cobra.Command, args []string) {
			if verbose {
				logLevel.Set(slog.LevelDebug)
			}
		},
	}
	root.PersistentFlags().BoolVarP(&verbose, "verbose", "v", false, "enable verbose logging")

	root.AddCommand(snapshotCmd())
	root.AddCommand(replicateCmd())
	root.AddCommand(watchCmd())
	root.AddCommand(restoreCmd())
	root.AddCommand(sentinelCheckCmd())
	root.AddCommand(opmenuCmd())

	if err := root.Execute(); err != nil {
		os.Exit(1)
	}
}
