package accountlock

import (
	"errors"
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

// TestLockDoesNotRecordAnAlreadyLockedShell covers a store/OS desync: if
// the account is already shut out when Lock runs, recording its current
// nologin shell as "previous" would make the eventual Unlock restore it
// to nologin — locked forever, silently.
func TestLockDoesNotRecordAnAlreadyLockedShell(t *testing.T) {
	sys := OSAccounts{NologinShell: "/usr/sbin/nologin"}
	for shell, wantEmpty := range map[string]bool{
		"/bin/bash":         false,
		"/usr/sbin/nologin": true,
		"/sbin/nologin":     true,
		"/bin/false":        true,
		"":                  true,
	} {
		if got := isNoLoginShell(shell, sys.NologinShell); got != wantEmpty {
			t.Errorf("isNoLoginShell(%q) = %v, want %v", shell, got, wantEmpty)
		}
	}
}

// failingSystem refuses to unlock one specific user.
type failingSystem struct {
	*fakeSystem
	failOn string
}

func (f *failingSystem) Unlock(user, shell string) error {
	if user == f.failOn {
		return errors.New("usermod: user does not exist")
	}
	return f.fakeSystem.Unlock(user, shell)
}

func TestReconcileKeepsGoingPastAFailedUnlock(t *testing.T) {
	store := newTestStore(t)
	sys := &failingSystem{fakeSystem: newFakeSystem(), failOn: "bravo"}
	now := time.Date(2026, 9, 20, 12, 0, 0, 0, time.UTC)

	for _, user := range []string{"alpha", "bravo", "charlie"} {
		if err := Add(store, sys.fakeSystem, user, "test", time.Minute, now); err != nil {
			t.Fatal(err)
		}
	}

	_, expired, err := Reconcile(store, sys, now.Add(time.Hour))
	if err == nil {
		t.Error("expected the failing unlock to be reported")
	}
	if len(expired) != 2 {
		t.Errorf("expected the other two locks to still be lifted, got %v", expired)
	}
	if sys.locked["charlie"] {
		t.Error("a lock after the failing one was never lifted — one failure stranded the rest")
	}

	// The one that failed stays in the store so the next pass retries it.
	locks, err := store.Load()
	if err != nil {
		t.Fatal(err)
	}
	if len(locks) != 1 || locks[0].User != "bravo" {
		t.Errorf("expected only the failed unlock kept, got %+v", locks)
	}
}

func TestIndefiniteLockPersistsUntilRemoved(t *testing.T) {
	st, sys := newTestStore(t), newFakeSystem()
	now := time.Now()
	if err := Add(st, sys, "example", "test", 0, now); err != nil {
		t.Fatal(err)
	}
	locks, err := st.Load()
	if err != nil || len(locks) != 1 || !locks[0].ExpiresAt.IsZero() {
		t.Fatalf("locks=%v err=%v", locks, err)
	}
	active, expired, err := Reconcile(st, sys, now.AddDate(10, 0, 0))
	if err != nil || len(active) != 1 || len(expired) != 0 || !sys.locked["example"] {
		t.Fatalf("active=%v expired=%v err=%v", active, expired, err)
	}
	if err := Remove(st, sys, "example"); err != nil {
		t.Fatal(err)
	}
	if sys.locked["example"] {
		t.Fatal("explicit unlock failed")
	}
	if err := Add(st, sys, "invalid", "test", -time.Second, now); err == nil || sys.locked["invalid"] {
		t.Fatal("negative duration accepted")
	}
}

func TestOverlayKeepsLocksWithoutChangingUnrelatedAccounts(t *testing.T) {
	input := []byte("blocked:x:123:123::/home/blocked:/bin/bash\nteam:x:124:124::/home/team:/bin/bash\n")
	locks := []Lock{{User: "blocked", PreviousShell: "/bin/bash"}}
	got, err := Overlay("/etc/passwd", input, locks, "/usr/sbin/nologin")
	if err != nil {
		t.Fatal(err)
	}
	want := "blocked:x:123:123::/home/blocked:/usr/sbin/nologin\nteam:x:124:124::/home/team:/bin/bash\n"
	if string(got) != want {
		t.Fatalf("got %q", got)
	}
	shadow := []byte("blocked:hash:1:0:99999:7:::\n")
	got, err = Overlay("/etc/shadow", shadow, locks, "/usr/sbin/nologin")
	if err != nil {
		t.Fatal(err)
	}
	again, err := Overlay("/etc/shadow", got, locks, "/usr/sbin/nologin")
	if err != nil || string(again) != string(got) {
		t.Fatal("overlay is not idempotent")
	}
	if locks[0].PreviousShell != "/bin/bash" {
		t.Fatal("lost original shell")
	}
}
