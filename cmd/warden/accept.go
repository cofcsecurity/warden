package main

import (
	"fmt"
	"time"

	"github.com/spf13/cobra"

	"warden/internal/audit"
	"warden/internal/manifest"
	"warden/internal/store"
)

// acceptCmd re-baselines individual watched paths to what is on disk now,
// so a deliberate change stops being flagged (or reverted, once armed)
// without disarming the whole box.
func acceptCmd() *cobra.Command {
	var flagged bool
	cmd := &cobra.Command{
		Use:   "accept <path>... | --flagged",
		Short: "Make the current content of watched paths their new known-good state",
		Long: `Re-baselines only the named paths in the config-tier snapshot to what is on
disk right now, accepting a deletion if the file is gone. Every other
path keeps its baseline.

--flagged accepts every confirm-first path that has drifted (shadow,
firewall rules, units, user keys): the usual follow-up after hardening
work done while armed.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			p, err := loadPaths()
			if err != nil {
				return err
			}
			if flagged {
				if len(args) > 0 {
					return fmt.Errorf("accept: give paths or --flagged, not both")
				}
				args, err = flaggedDrift(p)
				if err != nil {
					return err
				}
				if len(args) == 0 {
					fmt.Println("accept: no confirm-first path has drifted")
					return nil
				}
			}
			if len(args) == 0 {
				return fmt.Errorf("accept: name at least one path, or use --flagged")
			}
			return runAccept(p, args)
		},
	}
	cmd.Flags().BoolVar(&flagged, "flagged", false, "accept every drifted confirm-first path")
	return cmd
}

// flaggedDrift lists confirm-first paths whose current state differs from
// the baseline.
func flaggedDrift(p paths) ([]string, error) {
	last, err := manifest.New(p.configManifestPath)
	if err != nil {
		return nil, err
	}
	current, err := manifest.Generate(watchPassPaths(last), classifyPath, last.Generation)
	if err != nil {
		return nil, err
	}
	var out []string
	for _, c := range manifest.Diff(last, current) {
		if classifyPath(c.Path) == manifest.ConfirmFirst {
			out = append(out, c.Path)
		}
	}
	return out, nil
}

func runAccept(p paths, targets []string) error {
	for _, path := range targets {
		if !coveredBy(configTierPaths, path) {
			return fmt.Errorf("accept: %s is not a watched path", path)
		}
	}

	last, err := manifest.New(p.configManifestPath)
	if err != nil {
		return err
	}
	fresh, err := manifest.Generate(targets, classifyPath, 0)
	if err != nil {
		return err
	}

	replace := map[string]bool{}
	for _, t := range targets {
		replace[t] = true
	}
	var records []manifest.Record
	for _, r := range last.Records {
		if !replace[r.Path] {
			records = append(records, r)
		}
	}
	records = append(records, fresh.Records...)

	st, err := store.New(p.storeRoot)
	if err != nil {
		return err
	}
	for _, r := range fresh.Records {
		content, err := manifest.Content(r)
		if err != nil {
			return fmt.Errorf("accept: read %s: %w", r.Path, err)
		}
		if err := store.Verify(r.Hash, content); err != nil {
			return fmt.Errorf("accept: file changed while reading: %w", err)
		}
		if _, err := st.Put(content); err != nil {
			return fmt.Errorf("accept: store %s: %w", r.Path, err)
		}
	}

	generation, err := allocateGeneration(p, tierConfig, last.Generation)
	if err != nil {
		return err
	}
	next := &manifest.Manifest{
		Generation:     generation,
		CreatedAt:      time.Now().UTC(),
		Records:        records,
		ApprovedGroups: last.ApprovedGroups,
	}
	if err := next.Archive(p.configManifestsDir); err != nil {
		return err
	}
	if err := next.SaveAs(p.configManifestPath); err != nil {
		return err
	}

	log, err := audit.New(p.auditLogPath)
	if err != nil {
		return err
	}
	defer log.Close()

	present := map[string]bool{}
	for _, r := range fresh.Records {
		present[r.Path] = true
	}
	for _, path := range targets {
		action, state := "accepted", "its current content"
		if !present[path] {
			action, state = "accepted-deletion", "its absence"
		}
		_ = log.Log("accept", action, map[string]any{"path": path, "generation": next.Generation})
		fmt.Printf("accepted: %s is now known-good for %s (generation %d)\n", state, path, next.Generation)
	}
	return nil
}
