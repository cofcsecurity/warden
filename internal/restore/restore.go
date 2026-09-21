// Package restore is the human-triggered "fix this now" path, separate
// from watch's automatic loop.
package restore

import (
	"fmt"
	"os"
	"os/exec"

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
	TargetMode  os.FileMode
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

		entry := PlanEntry{Path: r.Path, TargetHash: r.Hash, TargetMode: r.Mode}
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

// EntryResult reports what happened to one path during Apply.
type EntryResult struct {
	Path           string
	Skipped        bool // entry wasn't Changed, so nothing was done
	ServiceStopped string
	ServiceStarted string
	Err            error
}

// Apply restores every Changed path in entries: stop the mapped service (if
// any), write the known-good content, reverify the hash, restart the
// service. A failure on one path doesn't stop the rest — each gets its own
// EntryResult, which callers are expected to send to an audit.Logger.
func (r *Restorer) Apply(entries []PlanEntry) []EntryResult {
	results := make([]EntryResult, 0, len(entries))
	for _, e := range entries {
		results = append(results, r.applyOne(e))
	}
	return results
}

func (r *Restorer) applyOne(e PlanEntry) EntryResult {
	res := EntryResult{Path: e.Path}
	if !e.Changed {
		res.Skipped = true
		return res
	}

	content, err := r.store.Get(e.TargetHash)
	if err != nil {
		res.Err = fmt.Errorf("restore %s: read known-good content: %w", e.Path, err)
		return res
	}

	var unit string
	var hasService bool
	if r.services != nil {
		unit, hasService = r.services(e.Path)
	}

	// Never write through a symlink — same reasoning as watch's own
	// guard: os.WriteFile below follows the link, so a watched path
	// swapped for a link to somewhere else would turn this restore into
	// a write to a file the attacker chose. Fails this one entry; the
	// rest of the plan still applies.
	symlink, err := manifest.IsSymlink(e.Path)
	if err != nil {
		res.Err = fmt.Errorf("restore %s: %w", e.Path, err)
		return res
	}
	if symlink {
		res.Err = fmt.Errorf("restore %s: refusing to write through a symlink — this path is now a link, which is itself a tamper worth looking at; remove the link first if this is legitimate", e.Path)
		return res
	}

	if hasService {
		if err := systemctl("stop", unit); err != nil {
			res.Err = fmt.Errorf("restore %s: stop %s: %w", e.Path, unit, err)
			return res
		}
		res.ServiceStopped = unit
	}

	if err := os.WriteFile(e.Path, content, e.TargetMode); err != nil {
		res.Err = fmt.Errorf("restore %s: write: %w", e.Path, err)
		return res
	}

	if err := verifyHash(e.Path, e.TargetHash); err != nil {
		res.Err = fmt.Errorf("restore %s: %w", e.Path, err)
		return res
	}

	if hasService {
		if err := systemctl("start", unit); err != nil {
			res.Err = fmt.Errorf("restore %s: start %s: %w", e.Path, unit, err)
			return res
		}
		res.ServiceStarted = unit
	}

	return res
}

func systemctl(action, unit string) error {
	out, err := exec.Command("systemctl", action, unit).CombinedOutput()
	if err != nil {
		return fmt.Errorf("systemctl %s %s: %w: %s", action, unit, err, out)
	}
	return nil
}

func verifyHash(path, want string) error {
	m, err := manifest.Generate([]string{path}, nil, 0)
	if err != nil {
		return fmt.Errorf("reverify: %w", err)
	}
	if len(m.Records) != 1 || m.Records[0].Hash != want {
		return fmt.Errorf("reverify: hash mismatch after write")
	}
	return nil
}
