package main

import (
	"fmt"
	"os"
	"path/filepath"

	"warden/internal/fsutil"
	"warden/internal/manifest"
)

// Caller holds operation.lock. Valid conflicting generations remain immutable.
// Invalid regular-file archives are retained under unique quarantine names.
func (r *backupRecovery) archiveRecovered(tier snapshotTier, m *manifest.Manifest) error {
	if err := validateRecoveryManifest(m, 0); err != nil {
		return err
	}
	if err := verifyManifest(m, tier); err != nil {
		return err
	}
	dir := r.p.manifestsDirForTier(tier)
	path := manifest.ArchivePath(dir, m.Generation)
	info, err := os.Lstat(path)
	if os.IsNotExist(err) {
		return m.Archive(dir)
	}
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("refusing non-regular archive %s", path)
	}
	data, err := fsutil.ReadFile(path)
	if err != nil {
		return err
	}
	previous, invalid := manifest.Parse(data)
	if invalid == nil {
		invalid = validateRecoveryManifest(previous, m.Generation)
	}
	if invalid == nil {
		invalid = verifyManifest(previous, tier)
	}
	if invalid == nil {
		return m.Archive(dir)
	}
	quarantine, err := os.CreateTemp(dir, fmt.Sprintf("corrupt-manifest-%d-*.json", m.Generation))
	if err != nil {
		return err
	}
	name := quarantine.Name()
	if err := quarantine.Close(); err != nil {
		os.Remove(name)
		return err
	}
	if err := os.Rename(path, name); err != nil {
		os.Remove(name)
		return err
	}
	r.quarantined = append(r.quarantined, name)
	// Sync the retained directory entry before publishing a replacement.
	d, err := os.Open(filepath.Dir(path))
	if err == nil {
		err = d.Sync()
		d.Close()
	}
	if err != nil {
		return fmt.Errorf("archive retained at %s; directory sync failed: %w", name, err)
	}
	r.record("manifest-quarantined", "local archive", map[string]any{"tier": tier, "generation": m.Generation, "path": name})
	if err := m.Archive(dir); err != nil {
		return fmt.Errorf("invalid archive retained at %s; replacement failed: %w", name, err)
	}
	return nil
}
