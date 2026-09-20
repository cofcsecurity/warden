// Package replicate pushes new snapshot objects off-box, so a root
// compromise of the monitored host doesn't take the backups with it.
package replicate

import (
	"fmt"

	"warden/internal/manifest"
	"warden/internal/store"
)

// Target is where a Replicator pushes to. Both an SSH host and a local
// filesystem path (e.g. removable media, when no second box is available)
// satisfy this interface, so callers don't branch on which is configured.
//
// Every method must be additive-only: a Target implementation must never
// delete or overwrite something that's already there. A compromised source
// box can then never destroy prior backups, only add to them.
type Target interface {
	Has(hash string) (bool, error)
	Put(hash string, content []byte) error
	HasManifest(generation int) (bool, error)
	PutManifest(generation int, data []byte) error
}

// Replicator pushes store objects and manifest generations to a Target.
type Replicator struct {
	target Target
}

// New builds a Replicator against target.
func New(target Target) *Replicator {
	return &Replicator{target: target}
}

// Push replicates m: every object m's records reference that the target
// doesn't already have, then the manifest generation itself. Existing
// objects and generations are left untouched.
func (r *Replicator) Push(m *manifest.Manifest, manifestData []byte, st *store.Store) error {
	for _, rec := range m.Records {
		has, err := r.target.Has(rec.Hash)
		if err != nil {
			return fmt.Errorf("replicate: check %s: %w", rec.Hash, err)
		}
		if has {
			continue
		}

		content, err := st.Get(rec.Hash)
		if err != nil {
			return fmt.Errorf("replicate: read %s from local store: %w", rec.Hash, err)
		}
		if err := r.target.Put(rec.Hash, content); err != nil {
			return fmt.Errorf("replicate: push %s: %w", rec.Hash, err)
		}
	}

	hasManifest, err := r.target.HasManifest(m.Generation)
	if err != nil {
		return fmt.Errorf("replicate: check manifest generation %d: %w", m.Generation, err)
	}
	if hasManifest {
		return nil
	}
	if err := r.target.PutManifest(m.Generation, manifestData); err != nil {
		return fmt.Errorf("replicate: push manifest generation %d: %w", m.Generation, err)
	}
	return nil
}
