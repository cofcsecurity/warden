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
	p, err := loadPaths()
	if err != nil {
		return err
	}

	st, err := store.New(p.storeRoot)
	if err != nil {
		return err
	}
	log, err := audit.New(p.auditLogPath)
	if err != nil {
		return err
	}
	defer log.Close()

	armed, err := isArmed(p)
	if err != nil {
		return err
	}

	w := watch.New(p.configManifestPath, watchedPaths, classifyPath, armed, st, log)
	res, err := w.Check()
	if err != nil {
		return err
	}

	if err := log.Log("watch", "pass", map[string]any{
		"armed":         armed,
		"auto_restored": len(res.AutoRestored),
		"suppressed":    len(res.Suppressed),
		"flagged":       len(res.Flagged),
	}); err != nil {
		return err
	}

	fmt.Printf("armed: %t, auto-restored: %d, suppressed: %d, flagged: %d\n", armed, len(res.AutoRestored), len(res.Suppressed), len(res.Flagged))
	if !armed && len(res.Suppressed) > 0 {
		fmt.Println("note: disarmed — the paths above were left as-is. run 'warden arm' once hardening is done.")
	}
	return nil
}
