package main

import (
	"fmt"
	"os"
	"path/filepath"
	"syscall"
	"warden/internal/restore"
	"warden/internal/store"
)

func preflightRestore(p paths, entries []restore.PlanEntry) error {
	recovery := newBackupRecovery(p, nil)
	defer recovery.Close()
	local := store.Open(p.storeRoot)
	for _, e := range entries {
		if !e.Changed {
			continue
		}
		if _, err := local.Get(e.TargetHash); err != nil {
			if _, err := recovery.object(e.TargetHash); err != nil {
				return err
			}
		}
		info, err := os.Lstat(e.Path)
		if err != nil && !os.IsNotExist(err) {
			return err
		}
		if info != nil && !info.Mode().IsRegular() {
			return fmt.Errorf("unsupported restore destination: %s", e.Path)
		}
		parent := filepath.Dir(e.Path)
		info, err = os.Stat(parent)
		if err != nil {
			return err
		}
		if !info.IsDir() {
			return fmt.Errorf("restore parent is not a directory: %s", parent)
		}
		if err := syscall.Access(parent, 2); err != nil {
			return fmt.Errorf("restore parent is not writable: %w", err)
		}
	}
	return nil
}
