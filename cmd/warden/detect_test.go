package main

import (
	"os"
	"path/filepath"
	"testing"

	"warden/internal/detect"
	"warden/internal/manifest"
)

// TestCurrentlyProtectedOnlyReportsPathsThatExist asserts the structural
// invariant currentlyProtected relies on: every entry it returns actually
// exists on disk, with a tier/class drawn from the expected small set.
// Not asserting specific paths, since configTierPaths' entries (e.g.
// /etc/shadow) aren't guaranteed present on every OS this might run on
// (e.g. a developer's Mac, vs. the Linux boxes this is actually deployed
// to).
func TestCurrentlyProtectedOnlyReportsPathsThatExist(t *testing.T) {
	got := currentlyProtected()
	for _, pp := range got {
		if _, err := os.Stat(pp.Path); err != nil {
			t.Errorf("currentlyProtected reported %s but it doesn't exist: %v", pp.Path, err)
		}
		if pp.Tier != "config" && pp.Tier != "data" {
			t.Errorf("%s: unexpected tier %q", pp.Path, pp.Tier)
		}
		if pp.Class != "auto-restore" && pp.Class != "confirm-first" {
			t.Errorf("%s: unexpected class %q", pp.Path, pp.Class)
		}
	}
}

// TestCurrentlyProtectedClassifiesConfirmFirstCorrectly confirms the
// class assigned matches confirmFirstPaths, using whichever
// confirmFirstPaths entries actually exist on this machine (there's
// always at least one on Linux, and CI runs on Linux — see
// .github/workflows/ci.yml).
func TestCurrentlyProtectedClassifiesConfirmFirstCorrectly(t *testing.T) {
	got := currentlyProtected()
	byPath := map[string]protectedPath{}
	for _, pp := range got {
		byPath[pp.Path] = pp
	}
	for p := range confirmFirstPaths {
		if _, err := os.Stat(p); err != nil {
			continue // not present on this machine, nothing to check
		}
		pp, ok := byPath[p]
		if !ok {
			t.Errorf("%s exists and is in confirmFirstPaths but currentlyProtected didn't report it", p)
			continue
		}
		if pp.Class != "confirm-first" {
			t.Errorf("%s: expected class confirm-first, got %s", p, pp.Class)
		}
	}
}

// TestEveryDetectableConfigPathIsWatched keeps the two lists that have to
// agree from drifting apart: internal/detect knows a service's config
// paths, configTierPaths decides whether they're actually protected, and
// a path in the first but not the second means `warden detect` reports a
// service as found and unwatched on every box that runs it — a standing
// "you should fix this" for something shipped that way deliberately.
//
// Adding a service to detect without adding its paths here is the easy
// mistake; this fails on it rather than leaving it for someone to notice
// in the output during a competition.
func TestEveryDetectableConfigPathIsWatched(t *testing.T) {
	watched := map[string]bool{}
	for _, p := range configTierPaths {
		watched[p] = true
	}
	for _, p := range dataTierPaths {
		watched[p] = true
	}

	for _, svc := range detect.KnownServices {
		for _, cfg := range svc.ConfigPaths {
			if !watched[cfg] {
				t.Errorf("detect knows %s's config path %s, but it isn't in configTierPaths/dataTierPaths", svc.Name, cfg)
			}
		}
	}
}

// TestServiceForPathOnlyReturnsUnitsThatExist covers the reason
// serviceForPath checks disk at all: restore stops a unit before writing,
// so naming one that isn't installed turns a restore into a failure
// instead of a plain file write.
func TestServiceForPathOnlyReturnsUnitsThatExist(t *testing.T) {
	dir := t.TempDir()
	oldDirs := systemdUnitSearchDirs
	systemdUnitSearchDirs = []string{dir}
	defer func() { systemdUnitSearchDirs = oldDirs }()

	if _, ok := serviceForPath("/etc/nginx/nginx.conf"); ok {
		t.Error("expected no unit when nothing is installed on this box")
	}
	if _, ok := serviceForPath("/etc/passwd"); ok {
		t.Error("expected no unit for a path with no service at all")
	}

	// Only the RHEL-family name for this config file is installed here.
	if err := os.WriteFile(filepath.Join(dir, "chronyd.service"), []byte("[Unit]\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	unit, ok := serviceForPath("/etc/chrony/chrony.conf")
	if !ok || unit != "chronyd" {
		t.Errorf("expected the installed candidate (chronyd), got %q ok=%v", unit, ok)
	}

	// With both present, the first candidate wins, so the distro's own
	// primary name is preferred over the alias.
	if err := os.WriteFile(filepath.Join(dir, "chrony.service"), []byte("[Unit]\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	unit, _ = serviceForPath("/etc/chrony/chrony.conf")
	if unit != "chrony" {
		t.Errorf("expected the first installed candidate, got %q", unit)
	}
}

// TestClassificationFollowsTheAccessRecoveryRule pins the classification
// decisions that would be actively harmful to get backwards.
//
// Auto-restore is the stronger setting: the file is back to known-good
// within a watch cycle with nobody involved. Confirm-first leaves the
// attacker's version in place until a person acts — which is the right
// trade only where reverting automatically does more damage than
// waiting.
func TestClassificationFollowsTheAccessRecoveryRule(t *testing.T) {
	// The access path. Flagging these and waiting for a human deadlocks
	// exactly when it matters: an sshd_config or PAM stack edited to
	// lock the team out can't be fixed by a human who can't log in.
	for _, path := range []string{
		"/etc/ssh/sshd_config",
		"/etc/passwd",
		"/etc/group",
		"/etc/sudoers",
		"/etc/pam.d/common-auth",
		"/etc/pam.d/system-auth",
		"/etc/pam.d/sshd",
		"/etc/pam.d/sudo",
		"/etc/nsswitch.conf",
		"/etc/login.defs",
	} {
		if classifyPath(path) != manifest.SafeAutoRestore {
			t.Errorf("%s must be auto-restored: flagging it is useless if it's what locked us out", path)
		}
	}

	// Credential material and firewall rule files, where reverting
	// automatically undoes the team's own work (a password rotation, a
	// ban saved mid-incident) and buys nothing an auto-restore of
	// /etc/passwd or a live 'warden ban' doesn't already.
	for _, path := range []string{
		"/etc/shadow",
		"/etc/gshadow",
		"/etc/iptables/rules.v4",
		"/etc/sysconfig/iptables",
		"/etc/nftables.conf",
		"/etc/ufw/user.rules",
	} {
		if classifyPath(path) != manifest.ConfirmFirst {
			t.Errorf("%s must be confirm-first: auto-reverting it fights the team's own changes", path)
		}
	}
}
