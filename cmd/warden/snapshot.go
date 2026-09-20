package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"warden/internal/audit"
	"warden/internal/manifest"
	"warden/internal/store"
)

func snapshotCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "snapshot",
		Short: "Take a backup snapshot of the watched paths",
		RunE: func(cmd *cobra.Command, args []string) error {
			return runSnapshot()
		},
	}
}

func runSnapshot() error {
	st, err := store.New(objectsDir)
	if err != nil {
		return err
	}
	log, err := audit.New(auditLogPath)
	if err != nil {
		return err
	}
	defer log.Close()

	last, err := manifest.New(manifestPath)
	if err != nil {
		return err
	}

	next, err := manifest.Generate(watchedPaths, classifyPath, last.Generation+1)
	if err != nil {
		return err
	}

	for _, r := range next.Records {
		content, err := os.ReadFile(r.Path)
		if err != nil {
			return fmt.Errorf("snapshot: read %s: %w", r.Path, err)
		}
		if _, err := st.Put(content); err != nil {
			return fmt.Errorf("snapshot: store %s: %w", r.Path, err)
		}
	}

	if err := next.SaveAs(manifestPath); err != nil {
		return err
	}

	return log.Log("snapshot", "taken", map[string]any{
		"generation": next.Generation,
		"records":    len(next.Records),
	})
}
