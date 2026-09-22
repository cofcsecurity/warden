package watch

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"warden/internal/audit"
	"warden/internal/manifest"
	"warden/internal/store"
)

func setup(t *testing.T) (dir string, st *store.Store, log *audit.Logger) {
	t.Helper()
	dir = t.TempDir()

	st, err := store.New(filepath.Join(dir, "objects"))
	if err != nil {
		t.Fatal(err)
	}
	log, err = audit.New(filepath.Join(dir, "audit.log"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { log.Close() })
	return dir, st, log
}

// snapshotBaseline mimics what the snapshot command does: generate a
// manifest from the current state of paths, store each record's content,
// and save it as the live manifest. Watch itself never does this — it only
// ever reads a baseline established this way.
func snapshotBaseline(t *testing.T, manifestPath string, paths []string, classify manifest.Classify, st *store.Store) {
	t.Helper()
	m, err := manifest.Generate(paths, classify, 1)
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range m.Records {
		content, err := os.ReadFile(r.Path)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := st.Put(content); err != nil {
			t.Fatal(err)
		}
	}
	if err := m.SaveAs(manifestPath); err != nil {
		t.Fatal(err)
	}
}

func TestCheckAutoRestoresModifiedFile(t *testing.T) {
	dir, st, log := setup(t)

	confPath := filepath.Join(dir, "nginx.conf")
	if err := os.WriteFile(confPath, []byte("known-good"), 0o644); err != nil {
		t.Fatal(err)
	}

	manifestPath := filepath.Join(dir, "manifest.json")
	snapshotBaseline(t, manifestPath, []string{confPath}, nil, st)

	w := New(manifestPath, []string{confPath}, nil, true, st, log, nil)

	// A clean check right after the baseline should find nothing to do.
	res, err := w.Check()
	if err != nil {
		t.Fatal(err)
	}
	if len(res.AutoRestored) != 0 || len(res.Flagged) != 0 {
		t.Fatalf("expected a clean check against its own baseline, got %+v", res)
	}

	// Tamper with the file, then check again.
	if err := os.WriteFile(confPath, []byte("tampered"), 0o644); err != nil {
		t.Fatal(err)
	}

	res, err = w.Check()
	if err != nil {
		t.Fatal(err)
	}
	if len(res.AutoRestored) != 1 || res.AutoRestored[0] != confPath {
		t.Fatalf("expected %s to be auto-restored, got %+v", confPath, res.AutoRestored)
	}

	got, err := os.ReadFile(confPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "known-good" {
		t.Fatalf("got content %q, want %q", got, "known-good")
	}

	// Check does not persist a new baseline: the manifest on disk is
	// unchanged, still readable, still generation 1.
	after, err := manifest.New(manifestPath)
	if err != nil {
		t.Fatal(err)
	}
	if after.Generation != 1 {
		t.Fatalf("expected Check to leave the manifest's generation alone, got %d", after.Generation)
	}
}

func TestCheckDoesNotWriteManifest(t *testing.T) {
	dir, st, log := setup(t)

	confPath := filepath.Join(dir, "nginx.conf")
	if err := os.WriteFile(confPath, []byte("known-good"), 0o644); err != nil {
		t.Fatal(err)
	}

	manifestPath := filepath.Join(dir, "manifest.json")
	snapshotBaseline(t, manifestPath, []string{confPath}, nil, st)

	before, err := os.ReadFile(manifestPath)
	if err != nil {
		t.Fatal(err)
	}

	w := New(manifestPath, []string{confPath}, nil, true, st, log, nil)
	if _, err := w.Check(); err != nil {
		t.Fatal(err)
	}

	after, err := os.ReadFile(manifestPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(before) != string(after) {
		t.Fatalf("expected Check to leave the manifest file byte-for-byte untouched\nbefore: %s\nafter:  %s", before, after)
	}
}

func TestCheckSuppressesRestoreWhenDisarmed(t *testing.T) {
	dir, st, log := setup(t)

	confPath := filepath.Join(dir, "nginx.conf")
	if err := os.WriteFile(confPath, []byte("known-good"), 0o644); err != nil {
		t.Fatal(err)
	}

	manifestPath := filepath.Join(dir, "manifest.json")
	snapshotBaseline(t, manifestPath, []string{confPath}, nil, st)

	w := New(manifestPath, []string{confPath}, nil, false, st, log, nil)

	// Simulate a team member hardening this exact file during the
	// pre-arm window.
	if err := os.WriteFile(confPath, []byte("hardened-by-hand"), 0o644); err != nil {
		t.Fatal(err)
	}

	res, err := w.Check()
	if err != nil {
		t.Fatal(err)
	}
	if len(res.AutoRestored) != 0 {
		t.Fatalf("expected nothing auto-restored while disarmed, got %+v", res.AutoRestored)
	}
	if len(res.Suppressed) != 1 || res.Suppressed[0] != confPath {
		t.Fatalf("expected %s to be reported suppressed, got %+v", confPath, res.Suppressed)
	}

	got, err := os.ReadFile(confPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "hardened-by-hand" {
		t.Fatalf("disarmed watch must not touch the file, got %q", got)
	}
}

func TestCheckFlagsConfirmFirstChanges(t *testing.T) {
	dir, st, log := setup(t)

	sudoersPath := filepath.Join(dir, "sudoers")
	if err := os.WriteFile(sudoersPath, []byte("root ALL=(ALL) ALL"), 0o644); err != nil {
		t.Fatal(err)
	}

	classify := func(path string) manifest.Class { return manifest.ConfirmFirst }
	manifestPath := filepath.Join(dir, "manifest.json")
	snapshotBaseline(t, manifestPath, []string{sudoersPath}, classify, st)

	w := New(manifestPath, []string{sudoersPath}, classify, true, st, log, nil)

	if err := os.WriteFile(sudoersPath, []byte("attacker ALL=(ALL) NOPASSWD:ALL"), 0o644); err != nil {
		t.Fatal(err)
	}

	res, err := w.Check()
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Flagged) != 1 || res.Flagged[0] != sudoersPath {
		t.Fatalf("expected %s to be flagged, got %+v", sudoersPath, res.Flagged)
	}
	if len(res.AutoRestored) != 0 {
		t.Fatalf("confirm-first path should never be auto-restored, got %+v", res.AutoRestored)
	}

	got, err := os.ReadFile(sudoersPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "attacker ALL=(ALL) NOPASSWD:ALL" {
		t.Fatalf("confirm-first content should be untouched, got %q", got)
	}

	// An unresolved confirm-first drift should keep getting flagged on
	// every subsequent run, not go silent after the first one — watch
	// never updates its own baseline, so there's nothing to make it stop.
	res, err = w.Check()
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Flagged) != 1 || res.Flagged[0] != sudoersPath {
		t.Fatalf("expected the still-unresolved drift to be flagged again, got %+v", res)
	}
}

// TestCheckFlagsDeletedConfirmFirstPathRatherThanRestoringIt guards against
// a real bug: a Removed change has no New record, so a class check that
// only ever looks at change.New would silently treat a deleted
// ConfirmFirst path (e.g. someone deleting /etc/shadow) as ordinary
// SafeAutoRestore drift and restore it, instead of flagging it the same
// way a modified ConfirmFirst path always is.
func TestCheckFlagsDeletedConfirmFirstPathRatherThanRestoringIt(t *testing.T) {
	dir, st, log := setup(t)

	sudoersPath := filepath.Join(dir, "sudoers")
	if err := os.WriteFile(sudoersPath, []byte("root ALL=(ALL) ALL"), 0o644); err != nil {
		t.Fatal(err)
	}

	classify := func(path string) manifest.Class { return manifest.ConfirmFirst }
	manifestPath := filepath.Join(dir, "manifest.json")
	snapshotBaseline(t, manifestPath, []string{sudoersPath}, classify, st)

	w := New(manifestPath, []string{sudoersPath}, classify, true, st, log, nil)

	if err := os.Remove(sudoersPath); err != nil {
		t.Fatal(err)
	}

	res, err := w.Check()
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Flagged) != 1 || res.Flagged[0] != sudoersPath {
		t.Fatalf("expected the deleted confirm-first path to be flagged, got %+v", res)
	}
	if len(res.AutoRestored) != 0 {
		t.Fatalf("a deleted confirm-first path must never be silently restored, got %+v", res.AutoRestored)
	}
	if _, err := os.Stat(sudoersPath); !os.IsNotExist(err) {
		t.Fatalf("expected the path to remain deleted, got err=%v", err)
	}
}

// TestCheckNeverWritesThroughASymlink covers the attack this guard
// exists for: a SafeAutoRestore path replaced by a link to something
// else entirely, so that the next auto-restore would write known-good
// bytes over the attacker's chosen target instead.
func TestCheckNeverWritesThroughASymlink(t *testing.T) {
	dir, st, log := setup(t)

	confPath := filepath.Join(dir, "nginx.conf")
	if err := os.WriteFile(confPath, []byte("known-good"), 0o644); err != nil {
		t.Fatal(err)
	}
	manifestPath := filepath.Join(dir, "manifest.json")
	snapshotBaseline(t, manifestPath, []string{confPath}, nil, st)

	// Red team's move: swap the watched path for a link to a file they
	// want overwritten, with different content so it also reads as drift.
	victim := filepath.Join(dir, "shadow")
	if err := os.WriteFile(victim, []byte("root:$6$real-hash:::::::"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(confPath); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(victim, confPath); err != nil {
		t.Fatal(err)
	}

	w := New(manifestPath, []string{confPath}, nil, true /* armed */, st, log, nil)
	res, err := w.Check()
	if err != nil {
		t.Fatal(err)
	}

	if len(res.AutoRestored) != 0 {
		t.Errorf("must never auto-restore through a symlink, restored: %v", res.AutoRestored)
	}
	if len(res.Flagged) != 1 || res.Flagged[0] != confPath {
		t.Errorf("expected the symlinked path to be flagged instead, got %v", res.Flagged)
	}

	got, err := os.ReadFile(victim)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "root:$6$real-hash:::::::" {
		t.Errorf("the symlink target was written through: %q", got)
	}
}

// TestAutoRestoreReloadsTheOwningService covers the half of auto-restore
// that isn't writing the file: sshd, nginx and the rest parse their
// config once at startup, so a restored file changes nothing for the
// running process until it re-reads. Without the reload, watch reports a
// box as repaired while the attacker's settings are still live — and
// restoring sshd_config after being locked out helps nobody.
func TestAutoRestoreReloadsTheOwningService(t *testing.T) {
	dir, st, log := setup(t)

	confPath := filepath.Join(dir, "sshd_config")
	if err := os.WriteFile(confPath, []byte("PermitRootLogin no\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	manifestPath := filepath.Join(dir, "manifest.json")
	snapshotBaseline(t, manifestPath, []string{confPath}, nil, st)

	if err := os.WriteFile(confPath, []byte("PermitRootLogin yes\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	var reloaded []string
	w := New(manifestPath, []string{confPath}, nil, true, st, log, func(path string) error {
		reloaded = append(reloaded, path)
		return nil
	})

	res, err := w.Check()
	if err != nil {
		t.Fatal(err)
	}
	if len(res.AutoRestored) != 1 {
		t.Fatalf("expected the drift restored, got %+v", res)
	}
	if len(reloaded) != 1 || reloaded[0] != confPath {
		t.Errorf("expected the restored path handed to reload, got %v", reloaded)
	}
	if len(res.ReloadErrors) != 0 {
		t.Errorf("expected no reload errors, got %v", res.ReloadErrors)
	}
}

// TestReloadFailureDoesNotAbortThePass: the file is already back to
// known-good by the time reload runs, and the remaining drifted paths
// still need restoring. A service that won't reload is reported, not
// thrown.
func TestReloadFailureDoesNotAbortThePass(t *testing.T) {
	dir, st, log := setup(t)

	first := filepath.Join(dir, "nginx.conf")
	second := filepath.Join(dir, "redis.conf")
	for _, f := range []string{first, second} {
		if err := os.WriteFile(f, []byte("known-good\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	manifestPath := filepath.Join(dir, "manifest.json")
	snapshotBaseline(t, manifestPath, []string{first, second}, nil, st)

	for _, f := range []string{first, second} {
		if err := os.WriteFile(f, []byte("tampered\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	w := New(manifestPath, []string{first, second}, nil, true, st, log, func(path string) error {
		return errors.New("unit failed to reload")
	})

	res, err := w.Check()
	if err != nil {
		t.Fatalf("a failed reload must not fail the pass: %v", err)
	}
	if len(res.AutoRestored) != 2 {
		t.Errorf("expected both paths restored despite the reload failures, got %+v", res.AutoRestored)
	}
	if len(res.ReloadErrors) != 2 {
		t.Errorf("expected both reload failures reported, got %v", res.ReloadErrors)
	}
	for _, f := range []string{first, second} {
		content, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		if string(content) != "known-good\n" {
			t.Errorf("%s was not restored: %q", f, content)
		}
	}
}

func TestCheckHonorsChangedProfile(t *testing.T) {
	dir, st, log := setup(t)
	path := filepath.Join(dir, "config")
	baseline := filepath.Join(dir, "manifest.json")
	if err := os.WriteFile(path, []byte("old"), 0600); err != nil {
		t.Fatal(err)
	}
	snapshotBaseline(t, baseline, []string{path}, nil, st)
	if err := os.WriteFile(path, []byte("new"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := New(baseline, nil, nil, true, st, log, nil).Check(); err != nil {
		t.Fatal(err)
	}
	content, _ := os.ReadFile(path)
	if string(content) != "new" {
		t.Fatal("restored a path removed from profile")
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	res, err := New(baseline, []string{path}, func(string) manifest.Class { return manifest.ConfirmFirst }, true, st, log, nil).Check()
	if err != nil || len(res.Flagged) != 1 {
		t.Fatalf("result=%v err=%v", res, err)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatal("deleted confirm-first path was recreated")
	}
}
