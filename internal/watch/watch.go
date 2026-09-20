// Package watch runs a single integrity check pass: generate a fresh
// manifest, diff it against the last known-good generation, act on the
// differences, exit. It's meant to be invoked by a jittered systemd timer,
// not run as a long-lived daemon.
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
	store        *store.Store
	log          *audit.Logger
}

// New builds a Watcher. manifestPath is where the last known-good manifest
// lives; paths are what this pass watches; classify assigns each path's
// Class (safe-auto-restore vs confirm-first).
func New(manifestPath string, paths []string, classify manifest.Classify, st *store.Store, log *audit.Logger) *Watcher {
	return &Watcher{
		manifestPath: manifestPath,
		paths:        paths,
		classify:     classify,
		store:        st,
		log:          log,
	}
}

// Result summarizes one Check pass.
type Result struct {
	AutoRestored []string
	Flagged      []string
}

// Check runs one integrity check pass: generate, diff, act, save.
func (w *Watcher) Check() (*Result, error) {
	last, err := manifest.New(w.manifestPath)
	if err != nil {
		return nil, fmt.Errorf("watch: load last-known-good manifest: %w", err)
	}

	next, err := manifest.Generate(w.paths, w.classify, last.Generation+1)
	if err != nil {
		return nil, fmt.Errorf("watch: generate manifest: %w", err)
	}

	res := &Result{}

	for _, change := range manifest.Diff(last, next) {
		switch {
		case change.New != nil && change.New.Class == manifest.ConfirmFirst:
			res.Flagged = append(res.Flagged, change.Path)
			w.logChange("flagged", change)

		case change.Kind == manifest.Modified || change.Kind == manifest.Removed:
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

	next.Generation = last.Generation + 1
	if err := w.saveManifest(next); err != nil {
		return res, err
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

func (w *Watcher) saveManifest(m *manifest.Manifest) error {
	return m.SaveAs(w.manifestPath)
}

func writeFile(path string, content []byte, mode fs.FileMode) error {
	if err := os.WriteFile(path, content, mode); err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}
	return nil
}
