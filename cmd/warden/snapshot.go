package main

import (
	"fmt"
	"os"
	"sort"

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

	recovery := newBackupRecovery(p, nil)
	defer recovery.Close()
	st, err := recovery.store()
	if err != nil {
		return err
	}
	log, err := audit.New(p.auditLogPath)
	if err != nil {
		return err
	}
	defer log.Close()
	recovery.log = log

	manifestPath := p.manifestPathForTier(tier)
	manifestsDir := p.manifestsDirForTier(tier)

	armed, err := isArmed(p)
	if err != nil {
		return err
	}
	if _, statErr := os.Stat(manifestPath); os.IsNotExist(statErr) {
		generations, listErr := manifest.Generations(manifestsDir)
		if listErr != nil {
			return listErr
		}
		if armed || len(generations) > 0 {
			if err := recovery.ensureManifest(tier); err != nil {
				return err
			}
		}
	}
	last, err := manifest.New(manifestPath)
	if err != nil {
		return err
	}

	next, err := manifest.Generate(pathsForTier(tier), classifyPath, last.Generation+1)
	if err != nil {
		return err
	}

	// An armed box's config baseline is frozen: drift is something to
	// revert, never something to absorb.
	//
	// Without this, the two timers raced for it. snapshot and watch both
	// run every five minutes, jittered independently, so an attacker's
	// edit was reverted if watch happened to fire first and *became the
	// new known-good state* if snapshot did — roughly a coin flip, per
	// edit, silently. A backdoor that won that toss was then defended by
	// Warden rather than removed by it, and nothing in the audit log,
	// `status` or `alerts` would ever say so, because from the next pass
	// on there was no drift left to see.
	//
	// Config tier only. The data tier exists to back up service data
	// that legitimately changes all day — freezing that would just stop
	// taking backups.
	if armed && tier == tierConfig {
		var declined []string
		next.Records, declined = keepBaseline(last, next)
		if len(declined) > 0 {
			if err := log.Log("snapshot", "declined-drift", map[string]any{
				"tier":  string(tier),
				"paths": declined,
			}); err != nil {
				return err
			}
			fmt.Printf("snapshot: kept the existing baseline for %d drifted path(s); watch handles those, not snapshot\n", len(declined))
		}
	}

	newObjects := 0
	for _, r := range next.Records {
		// Skip anything already stored. While armed that's every record
		// (the baseline's content was stored when it was taken), which
		// also means this never reads a path that has since drifted or
		// been deleted — the record is frozen, so reading the file back
		// would either add an object nothing references or, for a
		// deleted path, fail the whole snapshot.
		if st.Has(r.Hash) {
			continue
		}
		// Recover a frozen baseline from replicas before reading changed live files.
		if armed && tier == tierConfig {
			if _, err := st.Get(r.Hash); err == nil {
				newObjects++
				continue
			}
		}
		content, err := os.ReadFile(r.Path)
		if err != nil {
			return fmt.Errorf("snapshot: read %s: %w", r.Path, err)
		}
		if err := store.Verify(r.Hash, content); err != nil {
			return fmt.Errorf("snapshot: %s changed or its baseline object is missing: %w", r.Path, err)
		}
		if _, err := st.Put(content); err != nil {
			return fmt.Errorf("snapshot: store %s: %w", r.Path, err)
		}
		newObjects++
	}

	// Nothing moved, so there's nothing to record: a new generation per
	// five minutes that's byte-identical to the last one is just a
	// directory full of duplicates for restore --snapshot to wade
	// through. This is the normal case on an armed, quiet box.
	if sameRecords(last.Records, next.Records) {
		if err := pruneOldObjects(p, st); err != nil {
			return fmt.Errorf("snapshot: prune: %w", err)
		}
		fmt.Printf("snapshot: %s tier unchanged at generation %d (%d path(s)).\n", tier, last.Generation, len(next.Records))
		return log.Log("snapshot", "unchanged", map[string]any{
			"tier":       string(tier),
			"generation": last.Generation,
		})
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

	fmt.Printf("snapshot: %s tier generation %d, %d path(s), %d new object(s).\n", tier, next.Generation, len(next.Records), newObjects)
	return log.Log("snapshot", "taken", map[string]any{
		"tier":        string(tier),
		"generation":  next.Generation,
		"records":     len(next.Records),
		"new_objects": newObjects,
	})
}

// keepBaseline merges a freshly generated manifest onto an existing
// baseline without letting anything new in: a path whose content changed
// keeps its baseline record, a path that's gone keeps it too (so watch
// still has known-good content to restore from), and a path that has
// appeared since is left out entirely. It returns the merged records and
// the paths whose current state was declined.
//
// The effect is that while armed, the only things that can change the
// config baseline are the two commands a human runs deliberately:
// 'warden accept' for one path, 'warden arm' for all of them.
func keepBaseline(last, next *manifest.Manifest) (records []manifest.Record, declined []string) {
	current := map[string]manifest.Record{}
	for _, r := range next.Records {
		current[r.Path] = r
	}

	baselined := map[string]bool{}
	for _, old := range last.Records {
		baselined[old.Path] = true
		now, present := current[old.Path]
		switch {
		case !present:
			declined = append(declined, old.Path) // deleted; watch restores it
		case now.Hash != old.Hash || now.Symlink != old.Symlink:
			declined = append(declined, old.Path)
		}
		records = append(records, old)
	}

	for _, r := range next.Records {
		if !baselined[r.Path] {
			declined = append(declined, r.Path) // new since the baseline
		}
	}

	sort.Strings(declined)
	return records, declined
}

// sameRecords reports whether two record sets describe identical state,
// ignoring order.
func sameRecords(a, b []manifest.Record) bool {
	if len(a) != len(b) {
		return false
	}
	byPath := make(map[string]manifest.Record, len(a))
	for _, r := range a {
		byPath[r.Path] = r
	}
	for _, r := range b {
		other, ok := byPath[r.Path]
		if !ok || other.Hash != r.Hash || other.Mode != r.Mode || other.Class != r.Class || other.Symlink != r.Symlink {
			return false
		}
	}
	return true
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
