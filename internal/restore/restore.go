// Package restore is the human-triggered "fix this now" path, separate
// from watch's automatic loop.
package restore

import (
	"fmt"

	"warden/internal/manifest"
	"warden/internal/store"
)

// ServiceMap resolves a watched path to the systemd unit that owns it, if
// any. Restoring a path with no mapped service just writes the file.
type ServiceMap func(path string) (unit string, ok bool)

// Restorer applies snapshots back to disk.
type Restorer struct {
	store    *store.Store
	services ServiceMap
}

// New builds a Restorer against st, using services to map watched paths to
// the systemd units that should be stopped/restarted around a write.
func New(st *store.Store, services ServiceMap) *Restorer {
	return &Restorer{store: st, services: services}
}

// PlanEntry is one file's before/after in a restore plan.
type PlanEntry struct {
	Path        string
	CurrentHash string // empty if the path doesn't currently exist
	TargetHash  string
	Changed     bool
}

// Plan computes, without touching disk, what Apply would do: current
// on-disk hash vs. the target snapshot's hash for each record covering
// target. Both restore --dry-run and opmenu's restore command (which
// defaults to dry-run) go through this.
func Plan(snapshot *manifest.Manifest, target string) ([]PlanEntry, error) {
	var entries []PlanEntry
	for _, r := range snapshot.Records {
		if target != "" && r.Path != target {
			continue
		}
		current, err := manifest.Generate([]string{r.Path}, nil, 0)
		if err != nil {
			return nil, fmt.Errorf("restore: read current state of %s: %w", r.Path, err)
		}

		entry := PlanEntry{Path: r.Path, TargetHash: r.Hash}
		if len(current.Records) == 1 {
			entry.CurrentHash = current.Records[0].Hash
		}
		entry.Changed = entry.CurrentHash != entry.TargetHash
		entries = append(entries, entry)
	}
	if len(entries) == 0 {
		return nil, fmt.Errorf("restore: no matching record for %q in snapshot", target)
	}
	return entries, nil
}

// Apply restores every path in entries that differs from its target: stop
// the mapped service (if any), write the known-good content, reverify the
// hash, restart the service. Callers send each step to an audit.Logger.
//
// TODO: stop/start via os/exec of systemctl, then write + reverify.
func (r *Restorer) Apply(entries []PlanEntry) error {
	return fmt.Errorf("restore: Apply not yet implemented")
}
