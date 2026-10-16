package main

import (
	"fmt"

	"warden/internal/manifest"
)

func (r *backupRecovery) highestGeneration(tier snapshotTier) (int, error) {
	gens, err := manifest.Generations(r.p.manifestsDirForTier(tier))
	if err != nil {
		return 0, err
	}
	highest := 0
	for _, g := range gens {
		if g > highest {
			highest = g
		}
	}
	if current, err := manifest.New(r.p.manifestPathForTier(tier)); err != nil {
		return 0, err
	} else if current.Generation > highest {
		highest = current.Generation
	}
	for _, src := range r.sources {
		target, err := r.target(src)
		if err != nil {
			return 0, fmt.Errorf("cannot check lineage on %s: %w", src.url, err)
		}
		remote, err := target.ManifestGenerations(string(tier))
		if err != nil {
			return 0, err
		}
		for _, g := range remote {
			if g > highest {
				highest = g
			}
		}
	}
	return highest, nil
}

// allocateGeneration consults replicas when local generation history is lost.
func allocateGeneration(p paths, tier snapshotTier, current int) (int, error) {
	gens, err := manifest.Generations(p.manifestsDirForTier(tier))
	if err != nil {
		return 0, err
	}
	if len(gens) == 0 {
		recovery := newBackupRecovery(p, nil)
		defer recovery.Close()
		highest, err := recovery.highestGeneration(tier)
		if err != nil {
			return 0, err
		}
		if highest > current {
			current = highest
		}
	}
	return manifest.NextGeneration(p.manifestsDirForTier(tier), current)
}
