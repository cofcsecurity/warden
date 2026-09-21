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
	"path/filepath"
	"sort"
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
	// Symlink records that Path itself was a symbolic link when this
	// record was generated (Hash/Mode/MTime still describe what it
	// pointed at, so content drift of the target is still detected).
	// Nothing may write *through* such a path — see Diff, watch, and
	// restore: replacing a watched path with a link to somewhere else is
	// how an attacker turns a restore into a write to a file of their
	// choosing. Omitted from the JSON when false, so manifests written
	// before this field existed parse unchanged.
	Symlink bool `json:"symlink,omitempty"`
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

// Parse decodes manifest JSON bytes with no backing file — e.g. a
// generation just fetched from a replication peer. The result has no
// path; call SaveAs before Save-ing it.
func Parse(data []byte) (*Manifest, error) {
	var m Manifest
	if err := json.Unmarshal(data, &m); err != nil {
		return nil, fmt.Errorf("manifest: parse: %w", err)
	}
	return &m, nil
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

// ArchivePath returns where a given generation lives under an archive dir.
func ArchivePath(dir string, generation int) string {
	return filepath.Join(dir, fmt.Sprintf("manifest-%d.json", generation))
}

// Archive writes m to dir under its generation number, leaving m's own
// backing path untouched. Unlike the live manifest.json, archived
// generations are never overwritten, so restore --snapshot <id> and
// store.Prune's "last N generations" rule both have something to read.
func (m *Manifest) Archive(dir string) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("manifest: create archive dir %s: %w", dir, err)
	}

	data, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return fmt.Errorf("manifest: encode: %w", err)
	}
	path := ArchivePath(dir, m.Generation)
	if err := os.WriteFile(path, data, 0o600); err != nil {
		return fmt.Errorf("manifest: archive %s: %w", path, err)
	}
	return nil
}

// LoadGeneration loads a specific archived generation from dir.
func LoadGeneration(dir string, generation int) (*Manifest, error) {
	path := ArchivePath(dir, generation)
	m, err := New(path)
	if err != nil {
		return nil, err
	}
	if m.Generation == 0 && generation != 0 {
		return nil, fmt.Errorf("manifest: no archived generation %d in %s", generation, dir)
	}
	return m, nil
}

// Generations returns the archived generation numbers found in dir, sorted
// oldest first.
func Generations(dir string) ([]int, error) {
	entries, err := os.ReadDir(dir)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("manifest: list %s: %w", dir, err)
	}

	var gens []int
	for _, e := range entries {
		var g int
		if _, err := fmt.Sscanf(e.Name(), "manifest-%d.json", &g); err == nil {
			gens = append(gens, g)
		}
	}
	sort.Ints(gens)
	return gens, nil
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
		// Lstat first, Stat second: some distros legitimately ship a
		// watched path as a symlink (RHEL's /etc/my.cnf, say), so the
		// link's target is still hashed and still watched for content
		// drift — but the fact that it *is* a link is recorded, since
		// nothing downstream may write through it blindly.
		linkInfo, err := os.Lstat(p)
		if os.IsNotExist(err) {
			continue
		}
		if err != nil {
			return nil, fmt.Errorf("manifest: lstat %s: %w", p, err)
		}
		isSymlink := linkInfo.Mode()&os.ModeSymlink != 0

		info, err := os.Stat(p)
		if os.IsNotExist(err) {
			continue // dangling symlink: nothing to hash
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
			Path:    p,
			Hash:    hash,
			Mode:    info.Mode(),
			MTime:   info.ModTime().UTC(),
			Class:   classify(p),
			Symlink: isSymlink,
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
			// A path that became (or stopped being) a symlink is a
			// change even when the content behind it hashes the same:
			// swapping a watched file for a link to /etc/shadow is
			// exactly the tamper that would otherwise read as "no
			// drift" right up until something wrote through it.
			if oldRec.Hash != newRec.Hash || oldRec.Symlink != newRec.Symlink {
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

// IsSymlink reports whether path itself is a symbolic link right now,
// independent of any recorded state. Every code path that writes a
// watched path back to disk checks this immediately before writing:
// os.WriteFile follows links, so without it "restore the known-good
// /etc/nginx/nginx.conf" becomes "write those bytes over whatever
// /etc/nginx/nginx.conf currently points at" — which an attacker with
// root gets to choose.
func IsSymlink(path string) (bool, error) {
	info, err := os.Lstat(path)
	if os.IsNotExist(err) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("manifest: lstat %s: %w", path, err)
	}
	return info.Mode()&os.ModeSymlink != 0, nil
}
