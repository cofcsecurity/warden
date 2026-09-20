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
	var tierFlag string

	cmd := &cobra.Command{
		Use:   "snapshot",
		Short: "Take a backup snapshot of the watched paths",
		RunE: func(cmd *cobra.Command, args []string) error {
			tier, err := parseTier(tierFlag)
			if err != nil {
				return err
			}
			return runSnapshot(tier)
		},
	}
	cmd.Flags().StringVar(&tierFlag, "tier", string(tierConfig), `snapshot tier: "config" (fast, frequent) or "data" (slow, larger)`)
	return cmd
}

func runSnapshot(tier snapshotTier) error {
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

	next, err := manifest.Generate(pathsForTier(tier), classifyPath, last.Generation+1)
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
	if err := next.Archive(manifestsDir); err != nil {
		return err
	}

	if err := pruneOldObjects(st); err != nil {
		return fmt.Errorf("snapshot: prune: %w", err)
	}

	return log.Log("snapshot", "taken", map[string]any{
		"tier":       string(tier),
		"generation": next.Generation,
		"records":    len(next.Records),
	})
}

// pruneOldObjects keeps every object referenced by the last
// retainGenerations archived manifests and drops the rest.
func pruneOldObjects(st *store.Store) error {
	gens, err := manifest.Generations(manifestsDir)
	if err != nil {
		return err
	}
	if len(gens) > retainGenerations {
		gens = gens[len(gens)-retainGenerations:]
	}

	keep := map[string]bool{}
	for _, g := range gens {
		m, err := manifest.LoadGeneration(manifestsDir, g)
		if err != nil {
			return err
		}
		for _, r := range m.Records {
			keep[r.Hash] = true
		}
	}

	return st.Prune(keep)
}
