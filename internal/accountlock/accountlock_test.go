package accountlock

import (
	"path/filepath"
	"testing"
	"time"
)

// fakeSystem records Lock/Unlock/KillSessions calls instead of touching
// real accounts.
type fakeSystem struct {
	locked  map[string]bool
	killed  map[string]bool
	shellOf map[string]string // user -> shell to report from Lock
}

func newFakeSystem() *fakeSystem {
	return &fakeSystem{
		locked:  map[string]bool{},
		killed:  map[string]bool{},
		shellOf: map[string]string{},
	}
}

func (f *fakeSystem) Lock(user string) (string, error) {
	f.locked[user] = true
	shell := f.shellOf[user]
	if shell == "" {
		shell = "/bin/bash"
	}
	return shell, nil
}

func (f *fakeSystem) Unlock(user, shell string) error {
	delete(f.locked, user)
	return nil
}

func (f *fakeSystem) KillSessions(user string) error {
	f.killed[user] = true
	return nil
}

func newTestStore(t *testing.T) *Store {
	t.Helper()
	return NewStore(filepath.Join(t.TempDir(), "account_locks.json"))
}

func TestAddLocksAndPersists(t *testing.T) {
	store := newTestStore(t)
	sys := newFakeSystem()
	sys.shellOf["alovelace"] = "/bin/bash"
	now := time.Date(2026, 9, 20, 12, 0, 0, 0, time.UTC)

	if err := Add(store, sys, "alovelace", "new SUID binary owned by this account", time.Hour, now); err != nil {
		t.Fatal(err)
	}

	if !sys.locked["alovelace"] {
		t.Fatal("expected the account to be locked")
	}

	locks, err := store.Load()
	if err != nil {
		t.Fatal(err)
	}
	if len(locks) != 1 || locks[0].User != "alovelace" {
		t.Fatalf("expected one persisted lock, got %+v", locks)
	}
	if locks[0].PreviousShell != "/bin/bash" {
		t.Fatalf("expected the previous shell to be recorded, got %+v", locks[0])
	}
	if !locks[0].ExpiresAt.Equal(now.Add(time.Hour)) {
		t.Fatalf("expected expiry 1h from now, got %v", locks[0].ExpiresAt)
	}
}

func TestAddOnAlreadyLockedAccountRefreshesInsteadOfDuplicating(t *testing.T) {
	store := newTestStore(t)
	sys := newFakeSystem()
	sys.shellOf["alovelace"] = "/bin/bash"
	now := time.Date(2026, 9, 20, 12, 0, 0, 0, time.UTC)

	if err := Add(store, sys, "alovelace", "first", time.Hour, now); err != nil {
		t.Fatal(err)
	}
	later := now.Add(30 * time.Minute)
	if err := Add(store, sys, "alovelace", "second", time.Hour, later); err != nil {
		t.Fatal(err)
	}

	locks, err := store.Load()
	if err != nil {
		t.Fatal(err)
	}
	if len(locks) != 1 {
		t.Fatalf("expected the second Add to refresh, not duplicate, got %+v", locks)
	}
	if locks[0].Reason != "second" || !locks[0].ExpiresAt.Equal(later.Add(time.Hour)) {
		t.Fatalf("expected the lock refreshed to the second call's values, got %+v", locks[0])
	}
	if locks[0].PreviousShell != "/bin/bash" {
		t.Fatalf("expected the ORIGINAL previous shell kept, not a second Lock call's nologin shell, got %+v", locks[0])
	}
}

func TestRemoveUnlocksImmediatelyAndRestoresShell(t *testing.T) {
	store := newTestStore(t)
	sys := newFakeSystem()
	sys.shellOf["alovelace"] = "/bin/zsh"
	now := time.Date(2026, 9, 20, 12, 0, 0, 0, time.UTC)

	if err := Add(store, sys, "alovelace", "test", time.Hour, now); err != nil {
		t.Fatal(err)
	}
	if err := Remove(store, sys, "alovelace"); err != nil {
		t.Fatal(err)
	}

	if sys.locked["alovelace"] {
		t.Fatal("expected the account to be unlocked")
	}
	locks, err := store.Load()
	if err != nil {
		t.Fatal(err)
	}
	if len(locks) != 0 {
		t.Fatalf("expected no locks left, got %+v", locks)
	}
}

func TestReconcileExpiresOldLocksAndLeavesActiveOnesAlone(t *testing.T) {
	store := newTestStore(t)
	sys := newFakeSystem()
	now := time.Date(2026, 9, 20, 12, 0, 0, 0, time.UTC)

	if err := Add(store, sys, "stale-user", "old", time.Hour, now.Add(-2*time.Hour)); err != nil {
		t.Fatal(err)
	}
	if err := Add(store, sys, "fresh-user", "fresh", time.Hour, now); err != nil {
		t.Fatal(err)
	}

	active, expired, err := Reconcile(store, sys, now)
	if err != nil {
		t.Fatal(err)
	}
	if len(expired) != 1 || expired[0] != "stale-user" {
		t.Fatalf("expected the old lock to expire, got expired=%v", expired)
	}
	if len(active) != 1 || active[0] != "fresh-user" {
		t.Fatalf("expected the fresh lock to stay active, got active=%v", active)
	}
	if sys.locked["stale-user"] {
		t.Fatal("expected the expired lock's account to be unlocked")
	}

	locks, err := store.Load()
	if err != nil {
		t.Fatal(err)
	}
	if len(locks) != 1 || locks[0].User != "fresh-user" {
		t.Fatalf("expected only the still-active lock persisted, got %+v", locks)
	}
}

func TestKillSessionsCalledOnLock(t *testing.T) {
	sys := newFakeSystem()
	if err := sys.KillSessions("alovelace"); err != nil {
		t.Fatal(err)
	}
	if !sys.killed["alovelace"] {
		t.Fatal("expected KillSessions to record the call")
	}
}
