package anomaly

import (
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"syscall"
)

// CheckSUID flags any setuid/setgid binary under dirs that didn't exist
// as of the last run — a classic local-privilege-escalation persistence
// technique. Bounded to a handful of common bin directories, not a full
// filesystem walk, matching the "bounded, high-signal" scope in
// docs/PLAN.md Phase 9.
func CheckSUID(baselineDir string, dirs []string) ([]Finding, error) {
	baselinePath := filepath.Join(baselineDir, "suid.json")
	bootstrap := firstRun(baselinePath)
	old, err := loadBaseline(baselinePath)
	if err != nil {
		return nil, err
	}

	next := baseline{}
	var findings []Finding
	for _, dir := range dirs {
		entries, err := os.ReadDir(dir)
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}
			return nil, fmt.Errorf("anomaly: read dir %s: %w", dir, err)
		}
		for _, e := range entries {
			full := filepath.Join(dir, e.Name())
			info, err := os.Lstat(full)
			if err != nil {
				continue
			}
			// Symlinks are skipped: their mode bits aren't the target's,
			// and the target (if inside one of dirs too) is already
			// checked directly.
			if info.Mode()&os.ModeSymlink != 0 || info.IsDir() {
				continue
			}
			mode := info.Mode()
			if mode&(os.ModeSetuid|os.ModeSetgid) == 0 {
				continue
			}
			next[full] = "1"
			if bootstrap {
				continue
			}
			if _, existed := old[full]; existed {
				continue
			}
			findings = append(findings, Finding{
				Check:       "suid",
				Description: fmt.Sprintf("new setuid/setgid binary: %s (%s)", full, mode),
				Detail:      full,
				Culprit:     fileOwnerName(info),
				EventTime:   info.ModTime(),
			})
		}
	}

	if err := saveBaseline(baselinePath, next); err != nil {
		return nil, err
	}
	return findings, nil
}

// fileOwnerName resolves info's owning UID to a username, or "" if that
// isn't possible (no os/user backend, UID no longer maps to any account,
// ...) — an empty Culprit is already the documented "don't guess" signal
// callers respect.
func fileOwnerName(info os.FileInfo) string {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return ""
	}
	u, err := user.LookupId(strconv.FormatUint(uint64(stat.Uid), 10))
	if err != nil {
		return ""
	}
	return u.Username
}
