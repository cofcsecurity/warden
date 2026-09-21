package anomaly

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"syscall"
)

// CheckSUID flags any setuid/setgid binary under dirs that didn't exist
// as of the last run, and any already-known one whose *contents* changed
// — both classic local-privilege-escalation persistence techniques.
// Keying the baseline on path alone (what this used to do) missed the
// second one entirely: replacing the bytes of a setuid binary that's
// been on the box since the first scan — /usr/bin/sudo, say — is
// invisible to a check that only ever asks "is this path new?", and it's
// the more attractive move of the two, since it needs no new file for
// anyone to notice.
//
// Bounded to a handful of common bin directories, not a full filesystem
// walk, matching the "bounded, high-signal" scope in docs/PLAN.md Phase
// 9 — and only setuid/setgid files are ever hashed, which on a real box
// is a couple of dozen files, not the whole of /usr/bin.
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
			hash, err := hashFileContent(full)
			if err != nil {
				// Unreadable (a mount that vanished mid-scan, a
				// permission oddity) isn't itself a finding, and must
				// not abort the rest of the scan — but it also mustn't
				// silently reseed the baseline with a value that would
				// read as "unchanged" next pass, so the entry is left
				// out of the new baseline entirely and reported as new
				// again once it's readable.
				continue
			}
			next[full] = hash
			if bootstrap {
				continue
			}

			previous, existed := old[full]
			switch {
			case !existed:
				findings = append(findings, Finding{
					Check:       "suid",
					Description: fmt.Sprintf("new setuid/setgid binary: %s (%s)", full, mode),
					Detail:      full,
					Culprit:     fileOwnerName(info),
					EventTime:   info.ModTime(),
				})
			case previous == legacyPresenceValue:
				// Upgraded from the old path-only baseline: no recorded
				// content to compare against, so start watching this
				// path's contents from here rather than reporting every
				// known setuid binary as trojaned.
			case previous != hash:
				findings = append(findings, Finding{
					Check:       "suid",
					Description: fmt.Sprintf("setuid/setgid binary replaced in place: %s (%s) — same path, different contents than last scan", full, mode),
					Detail:      full,
					Culprit:     fileOwnerName(info),
					EventTime:   info.ModTime(),
				})
			}
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

// hashFileContent hashes a file by streaming it, so a large binary never
// has to be held in memory in full.
func hashFileContent(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()

	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}
