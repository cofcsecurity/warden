package main

import (
	"os"
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

// TestNewlyWatchedAuthAndFirewallPathsAreConfirmFirst pins the
// classification decisions that would be actively harmful to get wrong:
// reverting a PAM file can lock every account out of the box, and
// reverting a saved firewall ruleset undoes the team's own response to an
// attack in progress.
func TestNewlyWatchedAuthAndFirewallPathsAreConfirmFirst(t *testing.T) {
	for _, path := range []string{
		"/etc/pam.d/common-auth",
		"/etc/pam.d/system-auth",
		"/etc/pam.d/sshd",
		"/etc/pam.d/sudo",
		"/etc/nsswitch.conf",
		"/etc/login.defs",
		"/etc/iptables/rules.v4",
		"/etc/sysconfig/iptables",
		"/etc/nftables.conf",
		"/etc/ufw/user.rules",
	} {
		if classifyPath(path) != manifest.ConfirmFirst {
			t.Errorf("%s must be confirm-first, not auto-restored", path)
		}
	}
}
