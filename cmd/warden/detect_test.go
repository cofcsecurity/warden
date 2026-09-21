package main

import (
	"os"
	"testing"
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
