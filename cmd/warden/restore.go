package main

import (
	"fmt"

	"github.com/spf13/cobra"

	"warden/internal/manifest"
	"warden/internal/restore"
	"warden/internal/store"
)

func restoreCmd() *cobra.Command {
	var snapshotID string
	var apply bool

	cmd := &cobra.Command{
		Use:   "restore <target>",
		Short: "Restore a watched path from a snapshot",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runRestore(args[0], snapshotID, apply)
		},
	}
	cmd.Flags().StringVar(&snapshotID, "snapshot", "", "snapshot generation to restore from (default: latest)")
	cmd.Flags().BoolVar(&apply, "apply", false, "apply the restore instead of only showing what would change")
	return cmd
}

func runRestore(target, snapshotID string, apply bool) error {
	m, err := manifest.New(manifestPath)
	if err != nil {
		return err
	}
	if snapshotID != "" {
		// TODO: load the specific requested generation once manifest
		// generations are retained as separate files rather than one
		// mutable manifest.json.
		return fmt.Errorf("restore: --snapshot not yet implemented, only the latest generation is available")
	}

	entries, err := restore.Plan(m, target)
	if err != nil {
		return err
	}

	for _, e := range entries {
		status := "unchanged"
		if e.Changed {
			status = "DRIFTED"
		}
		fmt.Printf("%s  %s  current=%s target=%s\n", status, e.Path, e.CurrentHash, e.TargetHash)
	}

	if !apply {
		fmt.Println("dry run: pass --apply to restore")
		return nil
	}

	st, err := store.New(objectsDir)
	if err != nil {
		return err
	}
	r := restore.New(st, serviceForPath)
	return r.Apply(entries)
}
