package replicate

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
)

// FSTarget is a Target backed by a local (or removable-media) filesystem
// path, used when no second team-controlled box is available. It mirrors
// SSHTarget's layout so restore tooling doesn't need to care which backend
// produced a given root.
type FSTarget struct {
	root string
}

// NewFSTarget returns a Target rooted at root, creating it if necessary.
func NewFSTarget(root string) (*FSTarget, error) {
	if err := os.MkdirAll(filepath.Join(root, "objects"), 0o700); err != nil {
		return nil, fmt.Errorf("replicate: init %s: %w", root, err)
	}
	return &FSTarget{root: root}, nil
}

func (t *FSTarget) objectPath(hash string) string {
	return filepath.Join(t.root, "objects", hash[:2], hash)
}

func (t *FSTarget) manifestsDir(namespace string) string {
	return filepath.Join(t.root, "manifests-"+namespace)
}

func (t *FSTarget) manifestPath(namespace string, generation int) string {
	return filepath.Join(t.manifestsDir(namespace), fmt.Sprintf("manifest-%d.json", generation))
}

func (t *FSTarget) Has(hash string) (bool, error) {
	return exists(t.objectPath(hash))
}

func (t *FSTarget) Put(hash string, content []byte) error {
	return writeOnceLocal(t.objectPath(hash), content)
}

func (t *FSTarget) Get(hash string) ([]byte, error) {
	data, err := os.ReadFile(t.objectPath(hash))
	if err != nil {
		return nil, fmt.Errorf("replicate: read object %s: %w", hash, err)
	}
	return data, nil
}

func (t *FSTarget) HasManifest(namespace string, generation int) (bool, error) {
	return exists(t.manifestPath(namespace, generation))
}

func (t *FSTarget) PutManifest(namespace string, generation int, data []byte) error {
	return writeOnceLocal(t.manifestPath(namespace, generation), data)
}

func (t *FSTarget) GetManifest(namespace string, generation int) ([]byte, error) {
	path := t.manifestPath(namespace, generation)
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("replicate: read manifest %s: %w", path, err)
	}
	return data, nil
}

func (t *FSTarget) ManifestGenerations(namespace string) ([]int, error) {
	dir := t.manifestsDir(namespace)
	entries, err := os.ReadDir(dir)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("replicate: list %s: %w", dir, err)
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

func exists(path string) (bool, error) {
	_, err := os.Stat(path)
	if err == nil {
		return true, nil
	}
	if os.IsNotExist(err) {
		return false, nil
	}
	return false, err
}

// writeOnceLocal writes content to path unless it's already there,
// preserving additive-only semantics: never overwrite an existing file.
func writeOnceLocal(path string, content []byte) error {
	if present, err := exists(path); err != nil {
		return err
	} else if present {
		return nil
	}

	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return fmt.Errorf("replicate: mkdir for %s: %w", path, err)
	}

	tmp, err := os.CreateTemp(filepath.Dir(path), "obj-*.tmp")
	if err != nil {
		return fmt.Errorf("replicate: create temp for %s: %w", path, err)
	}
	defer os.Remove(tmp.Name())

	if _, err := tmp.Write(content); err != nil {
		tmp.Close()
		return fmt.Errorf("replicate: write %s: %w", path, err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("replicate: close temp for %s: %w", path, err)
	}
	if err := os.Rename(tmp.Name(), path); err != nil {
		return fmt.Errorf("replicate: commit %s: %w", path, err)
	}
	return nil
}
