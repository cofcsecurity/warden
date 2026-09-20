// Package replicate pushes new snapshot objects off-box, so a root
// compromise of the monitored host doesn't take the backups with it — and
// pulls them back, so a box that's been wiped and rebuilt has a way to
// recover its own prior backups from wherever they were replicated to.
package replicate

import (
	"fmt"

	"warden/internal/manifest"
	"warden/internal/store"
)

// Target is where a Replicator pushes to and a Retriever pulls from. Both
// an SSH host and a local filesystem path (e.g. removable media, or
// another box in a replication mesh) satisfy this interface, so callers
// don't branch on which is configured.
//
// Every write method must be additive-only: an implementation must never
// delete or overwrite something that's already there. A compromised
// source box can then never destroy prior backups, only add to them —
// pulling data back out (Get/GetManifest/ManifestGenerations) is a
// separate, explicit recovery action, not something Push ever does.
//
// namespace separates the two snapshot tiers (config vs. data) within one
// Target's root; it is not for separating different source boxes sharing
// one destination — that's handled by each source using a distinct root
// path (e.g. ssh://backup-box/from-boxB vs. .../from-boxF).
type Target interface {
	Has(hash string) (bool, error)
	Put(hash string, content []byte) error
	Get(hash string) ([]byte, error)

	HasManifest(namespace string, generation int) (bool, error)
	PutManifest(namespace string, generation int, data []byte) error
	GetManifest(namespace string, generation int) ([]byte, error)
	// ManifestGenerations returns every generation number the target has
	// for namespace, sorted oldest first.
	ManifestGenerations(namespace string) ([]int, error)
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
func (r *Replicator) Push(namespace string, m *manifest.Manifest, manifestData []byte, st *store.Store) error {
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

	hasManifest, err := r.target.HasManifest(namespace, m.Generation)
	if err != nil {
		return fmt.Errorf("replicate: check manifest generation %d: %w", m.Generation, err)
	}
	if hasManifest {
		return nil
	}
	if err := r.target.PutManifest(namespace, m.Generation, manifestData); err != nil {
		return fmt.Errorf("replicate: push manifest generation %d: %w", m.Generation, err)
	}
	return nil
}

// Retriever pulls manifest generations and their objects back from a
// Target — the reverse of Replicator, used to recover a box's own
// backups from a peer that holds a copy of them.
type Retriever struct {
	target Target
}

// NewRetriever builds a Retriever against target.
func NewRetriever(target Target) *Retriever {
	return &Retriever{target: target}
}

// LatestGeneration returns the highest generation number the target has
// for namespace.
func (r *Retriever) LatestGeneration(namespace string) (int, error) {
	gens, err := r.target.ManifestGenerations(namespace)
	if err != nil {
		return 0, fmt.Errorf("retrieve: list generations: %w", err)
	}
	if len(gens) == 0 {
		return 0, fmt.Errorf("retrieve: no generations available for %q on this target", namespace)
	}
	return gens[len(gens)-1], nil
}

// Pull fetches manifest generation from the target for namespace, along
// with every object it references, storing the objects in st. It does not
// touch any local manifest file — the caller decides whether and how to
// adopt the pulled manifest as live state (see cmd/warden's retrieve
// command, which treats this as a dry run unless --apply is given).
func (r *Retriever) Pull(namespace string, generation int, st *store.Store) (*manifest.Manifest, error) {
	data, err := r.target.GetManifest(namespace, generation)
	if err != nil {
		return nil, fmt.Errorf("retrieve: fetch manifest generation %d: %w", generation, err)
	}

	m, err := manifest.Parse(data)
	if err != nil {
		return nil, fmt.Errorf("retrieve: parse manifest generation %d: %w", generation, err)
	}

	for _, rec := range m.Records {
		if st.Has(rec.Hash) {
			continue
		}
		content, err := r.target.Get(rec.Hash)
		if err != nil {
			return nil, fmt.Errorf("retrieve: fetch object %s (%s): %w", rec.Hash, rec.Path, err)
		}
		if _, err := st.Put(content); err != nil {
			return nil, fmt.Errorf("retrieve: store object %s (%s): %w", rec.Hash, rec.Path, err)
		}
	}

	return m, nil
}
