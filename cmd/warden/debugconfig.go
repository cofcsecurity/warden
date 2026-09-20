package main

import (
	"fmt"

	"github.com/spf13/cobra"
)

// debugConfigCmd exists to answer one question right after a build: did
// -ldflags -X actually capture what I intended? It's meant to be run on the
// build machine against the freshly built binary, not deployed and invoked
// on a target box, so it's hidden from --help the same way opmenu is.
//
// It never prints buildTOTPSecret or buildReplicateKey — those are secrets,
// not build metadata — only whether each was set.
func debugConfigCmd() *cobra.Command {
	return &cobra.Command{
		Use:    "debug-config",
		Short:  "Print the per-competition values baked in at build time",
		Hidden: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			fmt.Printf("team_pubkey:          %s\n", orNotSet(buildTeamPubKey))
			fmt.Printf("team_from_ip:         %s\n", orNotSet(buildTeamFromIP))
			fmt.Printf("totp_secret_set:      %v\n", buildTOTPSecret != "")
			fmt.Printf("replicate_key_set:    %v\n", buildReplicateKey != "")
			fmt.Printf("autoban_enabled:      %v\n", buildAutobanEnabled != "")
			fmt.Println("replicate_targets:")
			targets := parseReplicateTargets(buildReplicateTargets)
			if len(targets) == 0 {
				fmt.Println("  (none configured)")
			}
			for _, t := range targets {
				fmt.Printf("  - url:       %s\n", t.url)
				fmt.Printf("    host_key:  %s\n", orNotSet(t.hostKey))
			}
			return nil
		},
	}
}

func orNotSet(s string) string {
	if s == "" {
		return "(not set)"
	}
	return s
}
