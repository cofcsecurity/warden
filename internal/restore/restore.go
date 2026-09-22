// Package restore is the human-triggered "fix this now" path, separate
// from watch's automatic loop.
package restore

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"warden/internal/fsutil"

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
	Control  Controller
	Validate func(string) error
}

// New builds a Restorer against st, using services to map watched paths to
// the systemd units that should be stopped/restarted around a write.
func New(st *store.Store, services ServiceMap) *Restorer {
	return &Restorer{store: st, services: services, Control: OSController{}}
}

// PlanEntry is one file's before/after in a restore plan.
type PlanEntry struct {
	Path        string
	CurrentHash string // empty if the path doesn't currently exist
	TargetHash  string
	TargetMode  os.FileMode
	CurrentMode os.FileMode
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
			entry.CurrentMode = current.Records[0].Mode
			if current.Records[0].Symlink {
				return nil, fmt.Errorf("restore: refusing symlink %s", r.Path)
			}
		}
		entry.Changed = entry.CurrentHash != entry.TargetHash || entry.CurrentMode != entry.TargetMode
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

// Controller exposes service state for transaction testing without real services.
type Controller interface {
	Active(string) (bool, error)
	Stop(string) error
	Start(string) error
}
type OSController struct{}

func (OSController) Active(unit string) (bool, error) {
	out, err := exec.Command("systemctl", "show", "--property=ActiveState", "--value", unit).Output()
	if err != nil {
		return false, err
	}
	switch string(out) {
	case "active\n", "reloading\n":
		return true, nil
	case "inactive\n", "failed\n":
		return false, nil
	default:
		return false, fmt.Errorf("service %s is transitioning", unit)
	}
}
func (OSController) Stop(unit string) error  { return systemctl("stop", unit) }
func (OSController) Start(unit string) error { return systemctl("start", unit) }

// Apply stages every file before stopping any unit. A failed transaction restores
// prior files before restarting services that were active when it began.
func (r *Restorer) Apply(entries []PlanEntry) []EntryResult {
	results := make([]EntryResult, len(entries))
	for i, e := range entries {
		results[i] = EntryResult{Path: e.Path, Skipped: !e.Changed}
	}
	type staged struct {
		index          int
		next, previous string
		existed        bool
		committed      bool
	}
	var files []staged
	units := map[string]bool{}
	var order []string
	fail := func(err error) {
		for i, e := range entries {
			if e.Changed {
				results[i].Err = err
			}
		}
	}
	defer func() {
		for _, f := range files {
			os.Remove(f.next)
			if f.previous != "" {
				os.Remove(f.previous)
			}
		}
	}()
	for i, e := range entries {
		results[i] = EntryResult{Path: e.Path, Skipped: !e.Changed}
		if !e.Changed {
			continue
		}
		data, err := r.store.Get(e.TargetHash)
		if err != nil {
			fail(err)
			return results
		}
		tmp, err := fsutil.Stage(e.Path, data, e.TargetMode)
		if err != nil {
			fail(err)
			return results
		}
		f := staged{index: i, next: tmp}
		if info, err := os.Lstat(e.Path); err == nil {
			before, err := fsutil.ReadFile(e.Path)
			if err != nil {
				os.Remove(tmp)
				fail(err)
				return results
			}
			f.previous, err = fsutil.Stage(e.Path, before, info.Mode())
			if err != nil {
				os.Remove(tmp)
				fail(err)
				return results
			}
			f.existed = true
		} else if !os.IsNotExist(err) {
			os.Remove(tmp)
			fail(err)
			return results
		}
		files = append(files, f)
		if r.services != nil {
			if unit, ok := r.services(e.Path); ok {
				if _, seen := units[unit]; !seen {
					units[unit] = false
					order = append(order, unit)
				}
			}
		}
	}
	// Inspect all units before changing any service state.
	for _, unit := range order {
		active, err := r.Control.Active(unit)
		if err != nil {
			fail(err)
			return results
		}
		units[unit] = active
	}
	var stopped []string
	restart := func() error {
		var errs []error
		for _, unit := range stopped {
			if err := r.Control.Start(unit); err != nil {
				errs = append(errs, err)
			} else {
				for i, e := range entries {
					if r.services != nil {
						u, _ := r.services(e.Path)
						if u == unit {
							results[i].ServiceStarted = unit
						}
					}
				}
			}
		}
		return errors.Join(errs...)
	}
	for _, unit := range order {
		if units[unit] {
			if err := r.Control.Stop(unit); err != nil {
				fail(errors.Join(err, restart()))
				return results
			}
			stopped = append(stopped, unit)
			for i, e := range entries {
				u, _ := r.services(e.Path)
				if u == unit {
					results[i].ServiceStopped = unit
				}
			}
		}
	}
	rollback := func(cause error) {
		var errs []error
		errs = append(errs, cause)
		rollbackOK := true
		for j := len(files) - 1; j >= 0; j-- {
			f := files[j]
			if !f.committed {
				continue
			}
			var err error
			if f.existed {
				err = os.Rename(f.previous, entries[f.index].Path)
			} else {
				err = os.Remove(entries[f.index].Path)
			}
			if err != nil {
				errs = append(errs, err)
				rollbackOK = false
			}
		}
		if rollbackOK {
			errs = append(errs, restart())
		} else {
			errs = append(errs, fmt.Errorf("rollback incomplete; stopped services require operator recovery"))
		}
		fail(errors.Join(errs...))
	}
	for j := range files {
		f := &files[j]
		e := entries[f.index]
		if link, err := manifest.IsSymlink(e.Path); err != nil || link {
			rollback(fmt.Errorf("destination changed before commit: %s", e.Path))
			return results
		}
		if err := os.Rename(f.next, e.Path); err != nil {
			rollback(err)
			return results
		}
		f.committed = true
		if err := verifyHash(e.Path, e.TargetHash); err != nil {
			rollback(err)
			return results
		}
		info, err := os.Stat(e.Path)
		if err != nil || info.Mode() != e.TargetMode {
			rollback(fmt.Errorf("mode verification failed: %s", e.Path))
			return results
		}
	}
	for _, unit := range order {
		if r.Validate != nil {
			if err := r.Validate(unit); err != nil {
				rollback(err)
				return results
			}
		}
	}
	if err := restart(); err != nil {
		fail(err)
	}
	return results
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
