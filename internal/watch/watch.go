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
	"fmt"
	"io/fs"
	"os"

	"warden/internal/audit"
	"warden/internal/manifest"
	"warden/internal/store"
)

// Watcher ties together the manifest, object store, and audit log needed to
// run one check pass.
type Watcher struct {
	manifestPath string
	paths        []string
	classify     manifest.Classify
	armed        bool
	store        *store.Store
	log          *audit.Logger
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
func New(manifestPath string, paths []string, classify manifest.Classify, armed bool, st *store.Store, log *audit.Logger) *Watcher {
	return &Watcher{
		manifestPath: manifestPath,
		paths:        paths,
		classify:     classify,
		armed:        armed,
		store:        st,
		log:          log,
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
}

// Check runs one integrity check pass: generate, diff, act. It does not
// write the manifest back — see the package doc for why.
func (w *Watcher) Check() (*Result, error) {
	last, err := manifest.New(w.manifestPath)
	if err != nil {
		return nil, fmt.Errorf("watch: load last-known-good manifest: %w", err)
	}

	// The generation number here is never persisted, so it's not
	// meaningful — Diff only compares records, not generations.
	next, err := manifest.Generate(w.paths, w.classify, last.Generation)
	if err != nil {
		return nil, fmt.Errorf("watch: generate manifest: %w", err)
	}

	res := &Result{}

	for _, change := range manifest.Diff(last, next) {
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

		switch {
		case class == manifest.ConfirmFirst:
			res.Flagged = append(res.Flagged, change.Path)
			res.FlaggedChanges = append(res.FlaggedChanges, change)
			w.logChange("flagged", change)

		case change.Kind == manifest.Modified || change.Kind == manifest.Removed:
			if !w.armed {
				res.Suppressed = append(res.Suppressed, change.Path)
				w.logChange("drift-suppressed", change)
				continue
			}
			if err := w.restore(change); err != nil {
				return res, fmt.Errorf("watch: restore %s: %w", change.Path, err)
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

	return res, nil
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
	if err := os.WriteFile(path, content, mode); err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}
	return nil
}
