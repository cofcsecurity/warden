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
	"warden/internal/fsutil"
)

// Store is a content-addressed object store rooted at a directory.
type Store struct {
	root          string
	recoverObject func(string) ([]byte, error)
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
	if _, err := s.readObject(hash); err == nil {
		return hash, nil
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

// SetRecovery supplies a fallback for missing or corrupt local objects.
func (s *Store) SetRecovery(recoverObject func(string) ([]byte, error)) {
	s.recoverObject = recoverObject
}

// ValidHash reports whether hash is a canonical SHA-256 object identifier.
func ValidHash(hash string) bool {
	if len(hash) != 64 {
		return false
	}
	for _, c := range hash {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}

// Verify checks bytes before they can be restored or cached under a hash.
func Verify(hash string, content []byte) error {
	if !ValidHash(hash) {
		return fmt.Errorf("store: invalid object hash %q", hash)
	}
	sum := sha256.Sum256(content)
	if hex.EncodeToString(sum[:]) != hash {
		return fmt.Errorf("store: hash mismatch for %s", hash)
	}
	return nil
}

// Get returns verified content, recovering and caching a backup when needed.
func (s *Store) Get(hash string) ([]byte, error) {
	if !ValidHash(hash) {
		return nil, fmt.Errorf("store: invalid object hash %q", hash)
	}
	content, localErr := s.readObject(hash)
	if localErr == nil {
		return content, nil
	}
	if s.recoverObject == nil {
		return nil, localErr
	}
	content, err := s.recoverObject(hash)
	if err != nil {
		return nil, fmt.Errorf("%v; recovery: %w", localErr, err)
	}
	if err := Verify(hash, content); err != nil {
		return nil, err
	}
	if _, err := s.Put(content); err != nil {
		return nil, fmt.Errorf("cache recovered object: %w", err)
	}
	return content, nil
}

func (s *Store) readObject(hash string) ([]byte, error) {
	f, err := fsutil.OpenRegular(s.objectPath(hash))
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
	if err := Verify(hash, data); err != nil {
		return nil, err
	}
	return data, nil
}

// Has reports whether an object with the given hash is already stored.
func (s *Store) Has(hash string) bool {
	if !ValidHash(hash) {
		return false
	}
	_, err := s.readObject(hash)
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

// Open reads an existing store without creating directories.
func Open(root string) *Store { return &Store{root: root} }
