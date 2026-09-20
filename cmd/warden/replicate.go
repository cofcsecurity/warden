package main

import (
	"fmt"

	"github.com/spf13/cobra"
)

func replicateCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "replicate",
		Short: "Push new snapshot objects to the off-host replication target",
		RunE: func(cmd *cobra.Command, args []string) error {
			return runReplicate()
		},
	}
}

func runReplicate() error {
	if buildReplicateURL == "" {
		return fmt.Errorf("replicate: no target configured (build with -ldflags -X main.buildReplicateURL=...)")
	}
	// TODO: dial buildReplicateURL (ssh://user@host/path or file:///path),
	// build a replicate.Target, and call replicate.Push with the current
	// manifest and any objects it references.
	return fmt.Errorf("replicate: not yet implemented")
}
