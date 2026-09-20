// Package manifest is the single source of truth for what known-good state
// looks like. Every other Warden component reads from or writes to it.
package manifest

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"time"
)

// Class controls how the watch loop responds to a change in a Record.
type Class string

const (
	// SafeAutoRestore records are reverted immediately when they drift.
	SafeAutoRestore Class = "safe-auto-restore"
	// ConfirmFirst records are never auto-reverted; drift is logged and
	// surfaced to an operator instead (keys, passwd, sudoers, and the
	// like).
	ConfirmFirst Class = "confirm-first"
)

// Record describes the known-good state of a single file.
type Record struct {
	Path  string      `json:"path"`
	Hash  string      `json:"hash"` // hex-encoded SHA-256 of file contents
	Mode  os.FileMode `json:"mode"`
	MTime time.Time   `json:"mtime"`
	Class Class       `json:"class"`
}

// Manifest is one generation of known-good state.
type Manifest struct {
	Generation int       `json:"generation"`
	CreatedAt  time.Time `json:"created_at"`
	Records    []Record  `json:"records"`

	path string
}

// New loads the manifest stored at path. A missing file returns an empty,
// unsaved manifest rather than an error.
func New(path string) (*Manifest, error) {
	m := &Manifest{path: path}

	data, err := os.ReadFile(path)
	switch {
	case os.IsNotExist(err):
		return m, nil
	case err != nil:
		return nil, fmt.Errorf("manifest: read %s: %w", path, err)
	}

	if err := json.Unmarshal(data, m); err != nil {
		return nil, fmt.Errorf("manifest: parse %s: %w", path, err)
	}
	m.path = path
	return m, nil
}

// Save writes the manifest back to its backing path as indented JSON.
func (m *Manifest) Save() error {
	if m.path == "" {
		return fmt.Errorf("manifest: no backing path set")
	}

	data, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return fmt.Errorf("manifest: encode: %w", err)
	}
	if err := os.WriteFile(m.path, data, 0o600); err != nil {
		return fmt.Errorf("manifest: write %s: %w", m.path, err)
	}
	return nil
}

// SaveAs sets the manifest's backing path and saves it there.
func (m *Manifest) SaveAs(path string) error {
	m.path = path
	return m.Save()
}

// Classify reports the class to use for a watched path.
type Classify func(path string) Class

// Generate builds a fresh manifest from the current on-disk state of paths.
// A path that doesn't exist is skipped rather than treated as an error, so
// its absence still shows up as a Removed change in the next Diff.
func Generate(paths []string, classify Classify, generation int) (*Manifest, error) {
	if classify == nil {
		classify = func(string) Class { return SafeAutoRestore }
	}

	m := &Manifest{
		Generation: generation,
		CreatedAt:  time.Now().UTC(),
	}

	for _, p := range paths {
		info, err := os.Stat(p)
		if os.IsNotExist(err) {
			continue
		}
		if err != nil {
			return nil, fmt.Errorf("manifest: stat %s: %w", p, err)
		}
		if info.IsDir() {
			continue
		}

		hash, err := hashFile(p)
		if err != nil {
			return nil, err
		}

		m.Records = append(m.Records, Record{
			Path:  p,
			Hash:  hash,
			Mode:  info.Mode(),
			MTime: info.ModTime().UTC(),
			Class: classify(p),
		})
	}

	return m, nil
}

func hashFile(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", fmt.Errorf("manifest: open %s: %w", path, err)
	}
	defer f.Close()

	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", fmt.Errorf("manifest: hash %s: %w", path, err)
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// ChangeKind classifies what happened to a path between two generations.
type ChangeKind string

const (
	Added    ChangeKind = "added"
	Removed  ChangeKind = "removed"
	Modified ChangeKind = "modified"
)

// Change describes a single difference between two manifest generations.
type Change struct {
	Kind ChangeKind
	Path string
	Old  *Record
	New  *Record
}

// Diff compares two manifests and returns what moved. A nil old manifest is
// treated as empty, so Diff(nil, new) reports everything in new as Added.
func Diff(old, new *Manifest) []Change {
	oldByPath := map[string]Record{}
	if old != nil {
		for _, r := range old.Records {
			oldByPath[r.Path] = r
		}
	}

	newByPath := map[string]Record{}
	if new != nil {
		for _, r := range new.Records {
			newByPath[r.Path] = r
		}
	}

	var changes []Change

	for path, newRec := range newByPath {
		newRec := newRec
		if oldRec, ok := oldByPath[path]; ok {
			oldRec := oldRec
			if oldRec.Hash != newRec.Hash {
				changes = append(changes, Change{Kind: Modified, Path: path, Old: &oldRec, New: &newRec})
			}
		} else {
			changes = append(changes, Change{Kind: Added, Path: path, New: &newRec})
		}
	}

	for path, oldRec := range oldByPath {
		oldRec := oldRec
		if _, ok := newByPath[path]; !ok {
			changes = append(changes, Change{Kind: Removed, Path: path, Old: &oldRec})
		}
	}

	return changes
}
