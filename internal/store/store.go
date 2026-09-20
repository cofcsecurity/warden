// Package store implements versioned, content-addressed storage for file
// contents using only the standard library — no git, tar, or rsync.
package store

import (
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

// Store is a content-addressed object store rooted at a directory.
type Store struct {
	root string
}

// New opens (creating if necessary) a store rooted at root.
func New(root string) (*Store, error) {
	if err := os.MkdirAll(filepath.Join(root, "objects"), 0o700); err != nil {
		return nil, fmt.Errorf("store: init %s: %w", root, err)
	}
	return &Store{root: root}, nil
}

func (s *Store) objectPath(hash string) string {
	return filepath.Join(s.root, "objects", hash[:2], hash)
}

// Put writes content to the store and returns its hex-encoded SHA-256 hash.
// If an object with that hash already exists, the write is skipped.
func (s *Store) Put(content []byte) (string, error) {
	sum := sha256.Sum256(content)
	hash := hex.EncodeToString(sum[:])

	path := s.objectPath(hash)
	if _, err := os.Stat(path); err == nil {
		return hash, nil // already have it
	}

	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return "", fmt.Errorf("store: mkdir for %s: %w", hash, err)
	}

	tmp, err := os.CreateTemp(filepath.Dir(path), "obj-*.tmp")
	if err != nil {
		return "", fmt.Errorf("store: create temp for %s: %w", hash, err)
	}
	defer os.Remove(tmp.Name()) // no-op once renamed

	gz := gzip.NewWriter(tmp)
	if _, err := gz.Write(content); err != nil {
		tmp.Close()
		return "", fmt.Errorf("store: compress %s: %w", hash, err)
	}
	if err := gz.Close(); err != nil {
		tmp.Close()
		return "", fmt.Errorf("store: finalize %s: %w", hash, err)
	}
	if err := tmp.Close(); err != nil {
		return "", fmt.Errorf("store: close temp for %s: %w", hash, err)
	}

	if err := os.Rename(tmp.Name(), path); err != nil {
		return "", fmt.Errorf("store: commit %s: %w", hash, err)
	}
	return hash, nil
}

// Get returns the decompressed content for hash.
func (s *Store) Get(hash string) ([]byte, error) {
	f, err := os.Open(s.objectPath(hash))
	if err != nil {
		return nil, fmt.Errorf("store: open %s: %w", hash, err)
	}
	defer f.Close()

	gz, err := gzip.NewReader(f)
	if err != nil {
		return nil, fmt.Errorf("store: decompress %s: %w", hash, err)
	}
	defer gz.Close()

	data, err := io.ReadAll(gz)
	if err != nil {
		return nil, fmt.Errorf("store: read %s: %w", hash, err)
	}
	return data, nil
}

// Has reports whether an object with the given hash is already stored.
func (s *Store) Has(hash string) bool {
	_, err := os.Stat(s.objectPath(hash))
	return err == nil
}

// Prune deletes any stored object whose hash is not in keep (mark-and-sweep
// retention; callers pass the union of hashes referenced by the last N
// manifests).
func (s *Store) Prune(keep map[string]bool) error {
	objectsDir := filepath.Join(s.root, "objects")
	entries, err := os.ReadDir(objectsDir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("store: list %s: %w", objectsDir, err)
	}

	for _, prefixEntry := range entries {
		if !prefixEntry.IsDir() {
			continue
		}
		prefixDir := filepath.Join(objectsDir, prefixEntry.Name())
		objects, err := os.ReadDir(prefixDir)
		if err != nil {
			return fmt.Errorf("store: list %s: %w", prefixDir, err)
		}
		for _, obj := range objects {
			if keep[obj.Name()] {
				continue
			}
			if err := os.Remove(filepath.Join(prefixDir, obj.Name())); err != nil {
				return fmt.Errorf("store: prune %s: %w", obj.Name(), err)
			}
		}
	}
	return nil
}
