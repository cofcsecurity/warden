package main

import (
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// isPattern reports whether a profile entry names more than one file.
func isPattern(entry string) bool {
	return strings.ContainsAny(entry, "*?[") || strings.HasSuffix(entry, "/**")
}

// matchesPattern reports whether path is covered by a profile entry: an
// exact path, a single-level glob, or a "/**" tree.
func matchesPattern(pattern, path string) bool {
	if pattern == path {
		return true
	}
	if root, ok := strings.CutSuffix(pattern, "/**"); ok {
		return strings.HasPrefix(path, root+"/")
	}
	ok, err := filepath.Match(pattern, path)
	return err == nil && ok
}

// coveredBy reports whether any entry covers path.
func coveredBy(patterns []string, path string) bool {
	for _, p := range patterns {
		if matchesPattern(p, path) {
			return true
		}
	}
	return false
}

// expandPatterns turns profile entries into the concrete files present
// right now: regular files and symlinks, never directories, never
// Warden's own files. maxBytes > 0 skips regular files larger than that.
func expandPatterns(patterns []string, maxBytes int64) []string {
	own := ownFiles()
	seen := map[string]bool{}
	var out []string
	add := func(path string) {
		if seen[path] || own(path) || inFlightTemp(filepath.Base(path)) {
			return
		}
		info, err := os.Lstat(path)
		if err != nil {
			return
		}
		switch {
		case info.Mode()&os.ModeSymlink != 0:
		case info.Mode().IsRegular():
			if maxBytes > 0 && info.Size() > maxBytes {
				return
			}
		default:
			return
		}
		seen[path] = true
		out = append(out, path)
	}
	for _, pattern := range patterns {
		switch {
		case strings.HasSuffix(pattern, "/**"):
			root := strings.TrimSuffix(pattern, "/**")
			_ = filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
				if err != nil {
					return nil
				}
				if d.IsDir() {
					if own(path) {
						return filepath.SkipDir
					}
					return nil
				}
				add(path)
				return nil
			})
		case isPattern(pattern):
			matches, _ := filepath.Glob(pattern)
			sort.Strings(matches)
			for _, m := range matches {
				add(m)
			}
		default:
			add(pattern)
		}
	}
	return out
}

// inFlightTemp reports Warden's own staging names (fsutil.Stage, writeOwnFile
// and the sudoers temp file). A watch pass that globbed one mid-write must
// not quarantine it; sshd, sudo and cron ignore such dotted names anyway.
func inFlightTemp(base string) bool {
	return strings.HasPrefix(base, ".tmp-") || strings.HasPrefix(base, ".warden-") || strings.HasSuffix(base, ".warden-tmp")
}

// watchedFiles is the concrete config-tier file list for this pass.
func watchedFiles() []string {
	return expandPatterns(configTierPaths, 0)
}

func pathsForTier(tier snapshotTier) []string {
	if tier == tierData {
		return expandPatterns(dataTierPaths, maxDataFileBytes)
	}
	return watchedFiles()
}

// ownFiles returns a predicate for Warden's own files. sentinel holds
// these; if watch held them too, the two would fight whenever pairing or a
// rekey legitimately changes one.
func ownFiles() func(string) bool {
	name, err := binaryName()
	if err != nil {
		return func(string) bool { return false }
	}
	exact := map[string]bool{}
	var prefixes []string
	if accounts, err := accessAccounts(); err == nil {
		for _, a := range accounts {
			exact[a.KeysPath] = true
			exact[a.Sudoers] = true
			exact[a.SSHDDropIn] = true
			prefixes = append(prefixes, a.Home+"/")
		}
	}
	names := []string{name}
	if bg := cfg.BreakGlassUser; bg != "" {
		names = append(names, bg)
		exact["/etc/cron.d/"+bg] = true
		prefixes = append(prefixes, "/usr/lib/"+bg+"/")
	}
	prefixes = append(prefixes, "/var/lib/"+name+"/", "/var/lib/"+name+"-peers/", "/usr/lib/"+name+"/")
	return func(path string) bool {
		if exact[path] {
			return true
		}
		for _, p := range prefixes {
			if strings.HasPrefix(path+"/", p) {
				return true
			}
		}
		if dir, base := filepath.Split(path); strings.HasPrefix(dir, systemdUnitDir+"/") {
			for _, n := range names {
				if strings.HasPrefix(base, n+"-") || base == n+".conf" {
					return true
				}
			}
		}
		return false
	}
}
