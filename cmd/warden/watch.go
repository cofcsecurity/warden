package main

import (
	"fmt"

	"github.com/spf13/cobra"

	"warden/internal/audit"
	"warden/internal/store"
	"warden/internal/watch"
)

func watchCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "watch",
		Short: "Run one integrity check pass over the watched paths",
		RunE: func(cmd *cobra.Command, args []string) error {
			return runWatch()
		},
	}
}

func runWatch() error {
	st, err := store.New(storeRoot)
	if err != nil {
		return err
	}
	log, err := audit.New(auditLogPath)
	if err != nil {
		return err
	}
	defer log.Close()

	w := watch.New(configManifestPath, watchedPaths, classifyPath, st, log)
	res, err := w.Check()
	if err != nil {
		return err
	}

	if err := log.Log("watch", "pass", map[string]any{
		"auto_restored": len(res.AutoRestored),
		"flagged":       len(res.Flagged),
	}); err != nil {
		return err
	}

	fmt.Printf("auto-restored: %d, flagged: %d\n", len(res.AutoRestored), len(res.Flagged))
	return nil
}
