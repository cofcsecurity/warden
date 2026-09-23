// Package watch runs a single integrity check pass: generate a fresh
// manifest, diff it against the last known-good generation, act on the
// differences, exit. It's meant to be invoked by a jittered systemd timer,
// not run as a long-lived daemon.
//
// Watch never writes the manifest it reads: the "last known-good"
// generation is whatever snapshot last produced (snapshot is also what
// populates the object store, via store.Put — watch only ever reads from
// it). If watch tried to maintain its own evolving baseline instead, it
// would have to introduce new generations of its own, and any hash it
// recorded for content it never called store.Put on would be
// unrestorable the next time that path drifted. Keeping watch read-only
// with respect to the manifest avoids that class of bug entirely.
package watch

import (
	"errors"
	"fmt"
	"io/fs"

	"warden/internal/audit"
	"warden/internal/fsutil"
	"warden/internal/manifest"
	"warden/internal/store"
)

// Reload is called once for each path auto-restored in a pass, so the
// service that owns it picks the known-good file back up. Writing the
// file alone doesn't do that: sshd, nginx and the rest parse their
// config at start and keep it in memory, so a restored config sits on
// disk while the running process goes on serving the attacker's
// version. A nil Reload skips this entirely (it's what the unit tests
// use, and it's harmless: the file is still restored).
//
// Implementations are expected to be idempotent per unit within a pass
// — several restored paths can map to the same service.
type Reload func(path string) error

// Watcher ties together the manifest, object store, and audit log needed to
// run one check pass.
type Watcher struct {
	manifestPath string
	paths        []string
	classify     manifest.Classify
	armed        bool
	store        *store.Store
	log          *audit.Logger
	reload       Reload
	Baseline     *manifest.Manifest
}

// New builds a Watcher. manifestPath is where the last known-good manifest
// lives; paths are what this pass watches; classify assigns each path's
// Class (safe-auto-restore vs confirm-first).
//
// armed gates auto-restore only. While disarmed — the default until a human
// runs `warden arm` — a SafeAutoRestore path that drifted is reported as
// Suppressed instead of being overwritten, so the box can be hardened
// (editing exactly these same config files) without watch fighting that
// work every few minutes. ConfirmFirst and unexpected-new-path handling are
// unaffected either way, since neither of those ever writes to disk.
func New(manifestPath string, paths []string, classify manifest.Classify, armed bool, st *store.Store, log *audit.Logger, reload Reload) *Watcher {
	return &Watcher{
		manifestPath: manifestPath,
		paths:        paths,
		classify:     classify,
		armed:        armed,
		store:        st,
		log:          log,
		reload:       reload,
	}
}

// Result summarizes one Check pass.
type Result struct {
	AutoRestored []string
	Suppressed   []string // would have been auto-restored, but disarmed
	Flagged      []string
	// FlaggedChanges carries the full manifest.Change for each entry in
	// Flagged (same order), including the new record's MTime — the caller
	// needs that to correlate a ConfirmFirst change against who had a
	// session open at the time (see cmd/warden's reactToGuardedChange).
	// Flagged itself stays a plain []string for callers that just want
	// the count/paths.
	FlaggedChanges []manifest.Change
	// ReloadErrors collects failures from Reload. The restores they
	// belong to still happened — these are reported so an operator
	// knows a service is running on something other than what's now on
	// disk.
	ReloadErrors []error
}

// Check runs one integrity check pass: generate, diff, act. It does not
// write the manifest back — see the package doc for why.
func (w *Watcher) Check() (*Result, error) {
	last, err := manifest.New(w.manifestPath)
	if err != nil {
		return nil, fmt.Errorf("watch: load last-known-good manifest: %w", err)
	}

	if w.Baseline != nil {
		last = w.Baseline
	}

	// A failed read is not a deletion. Exclude that path from this pass,
	// report the failure, and keep repairing independent paths.
	res := &Result{}
	var restoreErrors []error
	next := &manifest.Manifest{Generation: last.Generation}
	watched := map[string]bool{}
	for _, path := range w.paths {
		current, err := manifest.Generate([]string{path}, w.classify, last.Generation)
		if err != nil {
			restoreErrors = append(restoreErrors, fmt.Errorf("watch: read %s: %w", path, err))
			res.Flagged = append(res.Flagged, path)
			if w.log != nil {
				_ = w.log.Log("watch", "read-failed", map[string]any{"path": path, "error": err.Error()})
			}
			continue
		}
		watched[path] = true
		next.Records = append(next.Records, current.Records...)
	}
	for _, change := range manifest.Diff(last, next) {
		if !watched[change.Path] {
			continue
		}
		// A Removed change has no New record, so its class comes from
		// Old — otherwise a deleted ConfirmFirst path (e.g. /etc/shadow)
		// would fall through to the auto-restore branch below purely
		// because there's no New.Class to check, silently bypassing the
		// "never touched, always flagged" guarantee ConfirmFirst is
		// supposed to be.
		class := manifest.SafeAutoRestore
		switch {
		case change.New != nil:
			class = change.New.Class
		case change.Old != nil:
			class = change.Old.Class
		}

		if w.classify != nil {
			class = w.classify(change.Path)
		}
		switch {
		case class == manifest.ConfirmFirst:
			res.Flagged = append(res.Flagged, change.Path)
			res.FlaggedChanges = append(res.FlaggedChanges, change)
			w.logChange("flagged", change)

		case change.Kind == manifest.Modified || change.Kind == manifest.Removed:
			// A watched path that is now a symlink is never written
			// through, armed or not: os.WriteFile follows the link, so
			// "restore the known-good bytes" would become "write them
			// over whatever this now points at" — an attacker with root
			// picks the target (/etc/shadow, an authorized_keys, a
			// scored service's data file). Flagged for a human instead,
			// which is also the honest signal: the path being a link at
			// all is itself the tamper.
			symlink, err := manifest.IsSymlink(change.Path)
			if err != nil {
				restoreErrors = append(restoreErrors, fmt.Errorf("watch: check %s: %w", change.Path, err))
				res.Flagged = append(res.Flagged, change.Path)
				continue
			}
			if symlink {
				res.Flagged = append(res.Flagged, change.Path)
				res.FlaggedChanges = append(res.FlaggedChanges, change)
				w.logChange("flagged-symlink", change)
				continue
			}
			if !w.armed {
				res.Suppressed = append(res.Suppressed, change.Path)
				w.logChange("drift-suppressed", change)
				continue
			}
			if err := w.restore(change); err != nil {
				restoreErrors = append(restoreErrors, fmt.Errorf("watch: restore %s: %w", change.Path, err))
				continue
			}
			res.AutoRestored = append(res.AutoRestored, change.Path)
			w.logChange("auto-restored", change)

		case change.Kind == manifest.Added:
			// No known-good content exists for a new path, so it can only
			// be flagged, not restored.
			res.Flagged = append(res.Flagged, change.Path)
			w.logChange("flagged-unexpected", change)
		}
	}

	for _, path := range res.AutoRestored {
		if w.reload != nil {
			if err := w.reload(path); err != nil {
				res.ReloadErrors = append(res.ReloadErrors, err)
			}
		}
	}
	return res, errors.Join(restoreErrors...)
}

func (w *Watcher) restore(change manifest.Change) error {
	if change.Old == nil {
		return fmt.Errorf("no known-good content recorded for this path")
	}
	content, err := w.store.Get(change.Old.Hash)
	if err != nil {
		return fmt.Errorf("read known-good content from store: %w", err)
	}
	return writeFile(change.Path, content, change.Old.Mode)
}

func (w *Watcher) logChange(action string, change manifest.Change) {
	if w.log == nil {
		return
	}
	_ = w.log.Log("watch", action, map[string]any{
		"path": change.Path,
		"kind": change.Kind,
	})
}

func writeFile(path string, content []byte, mode fs.FileMode) error {
	if err := fsutil.WriteFile(path, content, mode); err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}
	return nil
}
