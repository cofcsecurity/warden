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

	manifestPath := p.manifestPathForTier(tier)
	manifestsDir := p.manifestsDirForTier(tier)

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

	if err := pruneOldObjects(p, st); err != nil {
		return fmt.Errorf("snapshot: prune: %w", err)
	}

	return log.Log("snapshot", "taken", map[string]any{
		"tier":       string(tier),
		"generation": next.Generation,
		"records":    len(next.Records),
	})
}

// pruneOldObjects keeps every object referenced by the last
// retainGenerations archived manifests of *either* tier and drops the
// rest — both tiers share one object store, so retention has to consider
// both lineages or it'll prune objects the other tier still needs.
func pruneOldObjects(p paths, st *store.Store) error {
	keep := map[string]bool{}

	for _, dir := range []string{p.configManifestsDir, p.dataManifestsDir} {
		gens, err := manifest.Generations(dir)
		if err != nil {
			return err
		}
		if len(gens) > retainGenerations {
			gens = gens[len(gens)-retainGenerations:]
		}
		for _, g := range gens {
			m, err := manifest.LoadGeneration(dir, g)
			if err != nil {
				return err
			}
			for _, r := range m.Records {
				keep[r.Hash] = true
			}
		}
	}

	return st.Prune(keep)
}
