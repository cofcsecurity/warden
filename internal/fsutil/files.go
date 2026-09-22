// Package fsutil provides atomic writes and nonblocking regular-file reads.
package fsutil

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"syscall"
)

func OpenRegular(path string) (*os.File, error) {
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() {
		f.Close()
		if err != nil {
			return nil, err
		}
		return nil, fmt.Errorf("not a regular file: %s", path)
	}
	return f, nil
}
func ReadFile(path string) ([]byte, error) {
	f, err := OpenRegular(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return io.ReadAll(f)
}

// Stage creates a complete replacement in the destination directory. It keeps
// existing ownership and rejects symlinks and non-regular destinations.
func Stage(path string, data []byte, mode os.FileMode) (name string, err error) {
	info, err := os.Lstat(path)
	if err != nil && !os.IsNotExist(err) {
		return "", err
	}
	if info != nil && !info.Mode().IsRegular() {
		return "", fmt.Errorf("refusing non-regular destination %s", path)
	}
	f, err := os.CreateTemp(filepath.Dir(path), ".warden-*")
	if err != nil {
		return "", err
	}
	name = f.Name()
	defer func() {
		f.Close()
		if err != nil {
			os.Remove(name)
		}
	}()
	if info != nil {
		if stat, ok := info.Sys().(*syscall.Stat_t); ok {
			if err = f.Chown(int(stat.Uid), int(stat.Gid)); err != nil {
				return name, err
			}
		}
	}
	if _, err = f.Write(data); err != nil {
		return name, err
	}
	if err = f.Chmod(mode); err != nil {
		return name, err
	}
	info, err = f.Stat()
	if err != nil {
		return name, err
	}
	if info.Mode() != mode {
		return name, fmt.Errorf("filesystem did not preserve requested mode for %s: got %v, want %v", path, info.Mode(), mode)
	}
	if err = f.Sync(); err != nil {
		return name, err
	}
	err = f.Close()
	return name, err
}
func WriteFile(path string, data []byte, mode os.FileMode) error {
	tmp, err := Stage(path, data, mode)
	if err != nil {
		return err
	}
	defer os.Remove(tmp)
	if err = os.Rename(tmp, path); err != nil {
		return err
	}
	dir, err := os.Open(filepath.Dir(path))
	if err != nil {
		return err
	}
	defer dir.Close()
	return dir.Sync()
}

// Lock serializes cooperating processes. The file is never unlinked.
func Lock(path string) (func(), error) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR|syscall.O_NOFOLLOW, 0600)
	if err != nil {
		return nil, err
	}
	if err = syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		f.Close()
		return nil, fmt.Errorf("another operation holds %s: %w", path, err)
	}
	return func() { syscall.Flock(int(f.Fd()), syscall.LOCK_UN); f.Close() }, nil
}
