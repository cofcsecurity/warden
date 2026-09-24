package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"warden/internal/audit"
	"warden/internal/fsutil"
	"warden/internal/manifest"
	"warden/internal/replicate"
	"warden/internal/store"
)

// Each operation keeps successful connections open and skips unavailable peers.
// Local replicas are tried before SSH, whose host keys remain pinned.
type backupRecovery struct {
	p           paths
	sources     []replicateTarget
	opened      map[string]replicate.Target
	failed      map[string]error
	closes      []func() error
	log         *audit.Logger
	quarantined []string
}

var openRecoveryTarget = dialRecoveryTarget

func dialRecoveryTarget(rawURL, hostKey string) (replicate.Target, func() error, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return nil, nil, err
	}
	if u.Scheme == "file" {
		target, err := replicate.OpenFSTarget(u.Path)
		if err != nil {
			return nil, nil, err
		}
		return target, func() error { return nil }, nil
	}
	return dialReplicateTarget(rawURL, hostKey)
}

func newBackupRecovery(p paths, log *audit.Logger) *backupRecovery {
	sources := parseReplicateTargets(buildReplicateTargets)
	sort.SliceStable(sources, func(i, j int) bool {
		return strings.HasPrefix(sources[i].url, "file://") && !strings.HasPrefix(sources[j].url, "file://")
	})
	return &backupRecovery{p: p, sources: sources, opened: map[string]replicate.Target{}, failed: map[string]error{}, log: log}
}
func (r *backupRecovery) Close() {
	for _, close := range r.closes {
		_ = close()
	}
}
func (r *backupRecovery) target(src replicateTarget) (replicate.Target, error) {
	if err := r.failed[src.url]; err != nil {
		return nil, err
	}
	if target := r.opened[src.url]; target != nil {
		return target, nil
	}
	target, close, err := openRecoveryTarget(src.url, src.hostKey)
	if err != nil {
		r.failed[src.url] = err
		return nil, err
	}
	r.opened[src.url] = target
	r.closes = append(r.closes, close)
	return target, nil
}
func (r *backupRecovery) record(action, source string, fields map[string]any) {
	if r.log == nil {
		return
	}
	fields["source"] = source
	_ = r.log.Log("recovery", action, fields)
}
func (r *backupRecovery) object(hash string) ([]byte, error) {
	if !store.ValidHash(hash) {
		return nil, fmt.Errorf("invalid object hash %q", hash)
	}
	var errs []error
	for _, src := range r.sources {
		target, err := r.target(src)
		if err == nil {
			var data []byte
			data, err = target.Get(hash)
			if err == nil {
				err = store.Verify(hash, data)
			}
			if err == nil {
				r.record("object-found", src.url, map[string]any{"hash": hash})
				return data, nil
			}
		}
		errs = append(errs, fmt.Errorf("%s: %w", src.url, err))
	}
	if len(errs) == 0 {
		return nil, fmt.Errorf("object %s unavailable; no backup targets configured", hash)
	}
	return nil, fmt.Errorf("object %s unavailable in configured backups: %w", hash, errors.Join(errs...))
}
func (r *backupRecovery) store() (*store.Store, error) {
	st, err := store.New(r.p.storeRoot)
	if err == nil {
		st.SetRecovery(r.object)
	}
	return st, err
}

// Validate recovered metadata before it can supply paths or object identifiers.
func validateRecoveryManifest(m *manifest.Manifest, generation int) error {
	if m.Generation <= 0 || generation > 0 && m.Generation != generation {
		return fmt.Errorf("unexpected manifest generation %d (requested %d)", m.Generation, generation)
	}
	seen := map[string]bool{}
	for _, rec := range m.Records {
		if !filepath.IsAbs(rec.Path) || filepath.Clean(rec.Path) != rec.Path || seen[rec.Path] {
			return fmt.Errorf("invalid or duplicate manifest path %q", rec.Path)
		}
		seen[rec.Path] = true
		if !store.ValidHash(rec.Hash) {
			return fmt.Errorf("invalid hash for %s", rec.Path)
		}
	}
	return nil
}

// Requested generations never fall back to an older one. Without a generation,
// choose the newest valid copy across local archives and configured replicas.
func (r *backupRecovery) manifest(tier snapshotTier, generation int) (*manifest.Manifest, error) {
	var errs []error
	type candidate struct {
		source     replicateTarget
		generation int
		local      bool
	}
	var candidates []candidate
	local := []int{generation}
	if generation == 0 {
		var err error
		local, err = manifest.Generations(r.p.manifestsDirForTier(tier))
		if err != nil {
			errs = append(errs, err)
		}
	}
	for _, g := range local {
		if g > 0 {
			candidates = append(candidates, candidate{generation: g, local: true})
		}
	}
	// An exact local archive needs no network lookup.
	if generation > 0 {
		// The live pointer may be the last local copy of this generation.
		if data, err := fsutil.ReadFile(r.p.manifestPathForTier(tier)); err == nil {
			if m, err := manifest.Parse(data); err == nil && validateRecoveryManifest(m, generation) == nil && verifyManifest(m, tier) == nil {
				return m, nil
			}
		}
		m, err := manifest.LoadGeneration(r.p.manifestsDirForTier(tier), generation)
		if err == nil {
			err = validateRecoveryManifest(m, generation)
			if err == nil {
				err = verifyManifest(m, tier)
			}
		}
		if err == nil {
			return m, nil
		}
	}
	for _, src := range r.sources {
		target, err := r.target(src)
		if err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", src.url, err))
			continue
		}
		gens := []int{generation}
		if generation == 0 {
			gens, err = target.ManifestGenerations(string(tier))
		}
		if err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", src.url, err))
			continue
		}
		for _, g := range gens {
			if g > 0 {
				candidates = append(candidates, candidate{source: src, generation: g})
			}
		}
	}
	sort.SliceStable(candidates, func(i, j int) bool { return candidates[i].generation > candidates[j].generation })
	for _, candidate := range candidates {
		var m *manifest.Manifest
		var err error
		source := "local archive"
		if candidate.local {
			m, err = manifest.LoadGeneration(r.p.manifestsDirForTier(tier), candidate.generation)
		} else {
			source = candidate.source.url
			target, _ := r.target(candidate.source)
			var data []byte
			data, err = target.GetManifest(string(tier), candidate.generation)
			if err == nil {
				m, err = manifest.Parse(data)
			}
		}
		if err == nil {
			err = validateRecoveryManifest(m, candidate.generation)
			if err == nil {
				err = verifyManifest(m, tier)
			}
		}
		if err == nil {
			r.record("manifest-found", source, map[string]any{"tier": tier, "generation": m.Generation})
			return m, nil
		}
		errs = append(errs, fmt.Errorf("%s generation %d: %w", source, candidate.generation, err))
	}
	if len(errs) == 0 {
		return nil, fmt.Errorf("no %s manifests in local archives or configured backups", tier)
	}
	return nil, fmt.Errorf("no usable %s manifest (generation %d) in local archives or configured backups: %w", tier, generation, errors.Join(errs...))
}

func (r *backupRecovery) loadManifest(tier snapshotTier, id string) (*manifest.Manifest, error) {
	if id != "" {
		g, err := strconv.Atoi(id)
		if err != nil || g <= 0 {
			return nil, fmt.Errorf("snapshot generation must be a positive integer")
		}
		return r.manifest(tier, g)
	}
	data, err := fsutil.ReadFile(r.p.manifestPathForTier(tier))
	if err == nil {
		m, parseErr := manifest.Parse(data)
		if parseErr == nil && validateRecoveryManifest(m, 0) == nil && verifyManifest(m, tier) == nil {
			return m, nil
		}
	}
	return r.manifest(tier, 0)
}

// Watch repairs missing metadata only; it never replaces an existing baseline.
func (r *backupRecovery) ensureManifest(tier snapshotTier) error {
	if _, err := os.Stat(r.p.manifestPathForTier(tier)); err == nil {
		return nil
	} else if !os.IsNotExist(err) {
		return err
	}
	m, err := r.manifest(tier, 0)
	if err != nil {
		return err
	}
	highest, err := r.highestGeneration(tier)
	if err != nil {
		return fmt.Errorf("automatic manifest recovery cannot verify lineage; use retrieve --allow-rollback for an explicit override: %w", err)
	}
	if m.Generation < highest {
		return fmt.Errorf("automatic manifest recovery would roll back from generation %d to %d; use retrieve --allow-rollback", highest, m.Generation)
	}
	if err := r.archiveRecovered(tier, m); err != nil {
		return err
	}
	data, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return err
	}
	path := r.p.manifestPathForTier(tier)
	tmp, err := os.CreateTemp(filepath.Dir(path), "manifest-recovery-*.tmp")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Link(tmp.Name(), path); err != nil && !os.IsExist(err) {
		return err
	}
	return nil
}
