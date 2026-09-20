package autoban

import (
	"path/filepath"
	"testing"
	"time"
)

// fakeFirewall records Block/Unblock calls instead of touching real
// iptables rules.
type fakeFirewall struct {
	blocked map[string]bool
}

func newFakeFirewall() *fakeFirewall {
	return &fakeFirewall{blocked: map[string]bool{}}
}

func (f *fakeFirewall) Block(ip string) error {
	f.blocked[ip] = true
	return nil
}

func (f *fakeFirewall) Unblock(ip string) error {
	delete(f.blocked, ip)
	return nil
}

func newTestStore(t *testing.T) *Store {
	t.Helper()
	return NewStore(filepath.Join(t.TempDir(), "banned_ips.json"))
}

func TestAddAppliesAndPersists(t *testing.T) {
	store := newTestStore(t)
	fw := newFakeFirewall()
	now := time.Date(2026, 9, 20, 12, 0, 0, 0, time.UTC)

	if err := Add(store, fw, "203.0.113.10", "guarded file touched", time.Hour, now); err != nil {
		t.Fatal(err)
	}

	if !fw.blocked["203.0.113.10"] {
		t.Fatal("expected the firewall to have blocked the IP")
	}

	bans, err := store.Load()
	if err != nil {
		t.Fatal(err)
	}
	if len(bans) != 1 || bans[0].IP != "203.0.113.10" {
		t.Fatalf("expected one persisted ban, got %+v", bans)
	}
	if !bans[0].ExpiresAt.Equal(now.Add(time.Hour)) {
		t.Fatalf("expected expiry 1h from now, got %v", bans[0].ExpiresAt)
	}
}

func TestAddOnAlreadyBannedIPRefreshesInsteadOfDuplicating(t *testing.T) {
	store := newTestStore(t)
	fw := newFakeFirewall()
	now := time.Date(2026, 9, 20, 12, 0, 0, 0, time.UTC)

	if err := Add(store, fw, "203.0.113.10", "first", time.Hour, now); err != nil {
		t.Fatal(err)
	}
	later := now.Add(30 * time.Minute)
	if err := Add(store, fw, "203.0.113.10", "second", time.Hour, later); err != nil {
		t.Fatal(err)
	}

	bans, err := store.Load()
	if err != nil {
		t.Fatal(err)
	}
	if len(bans) != 1 {
		t.Fatalf("expected the second Add to refresh, not duplicate, got %+v", bans)
	}
	if bans[0].Reason != "second" || !bans[0].ExpiresAt.Equal(later.Add(time.Hour)) {
		t.Fatalf("expected the ban refreshed to the second call's values, got %+v", bans[0])
	}
}

func TestRemoveUnblocksImmediately(t *testing.T) {
	store := newTestStore(t)
	fw := newFakeFirewall()
	now := time.Date(2026, 9, 20, 12, 0, 0, 0, time.UTC)

	if err := Add(store, fw, "203.0.113.10", "test", time.Hour, now); err != nil {
		t.Fatal(err)
	}
	if err := Remove(store, fw, "203.0.113.10"); err != nil {
		t.Fatal(err)
	}

	if fw.blocked["203.0.113.10"] {
		t.Fatal("expected the IP to be unblocked")
	}
	bans, err := store.Load()
	if err != nil {
		t.Fatal(err)
	}
	if len(bans) != 0 {
		t.Fatalf("expected no bans left, got %+v", bans)
	}
}

func TestReconcileExpiresOldBansAndKeepsActiveOnesApplied(t *testing.T) {
	store := newTestStore(t)
	fw := newFakeFirewall()
	now := time.Date(2026, 9, 20, 12, 0, 0, 0, time.UTC)

	if err := Add(store, fw, "203.0.113.10", "old", time.Hour, now.Add(-2*time.Hour)); err != nil {
		t.Fatal(err)
	}
	if err := Add(store, fw, "198.51.100.5", "fresh", time.Hour, now); err != nil {
		t.Fatal(err)
	}

	// Simulate the firewall having been flushed (e.g. a reboot) between
	// Add and Reconcile — the fresh ban's rule is gone until reapplied.
	fw.blocked = map[string]bool{}

	active, expired, err := Reconcile(store, fw, now)
	if err != nil {
		t.Fatal(err)
	}
	if len(expired) != 1 || expired[0] != "203.0.113.10" {
		t.Fatalf("expected the old ban to expire, got expired=%v", expired)
	}
	if len(active) != 1 || active[0] != "198.51.100.5" {
		t.Fatalf("expected the fresh ban to stay active, got active=%v", active)
	}
	if !fw.blocked["198.51.100.5"] {
		t.Fatal("expected Reconcile to re-apply the fresh ban's firewall rule")
	}
	if fw.blocked["203.0.113.10"] {
		t.Fatal("expected the expired ban to be unblocked")
	}

	bans, err := store.Load()
	if err != nil {
		t.Fatal(err)
	}
	if len(bans) != 1 || bans[0].IP != "198.51.100.5" {
		t.Fatalf("expected only the still-active ban persisted, got %+v", bans)
	}
}
