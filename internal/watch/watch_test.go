package watch

import (
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

func TestCheckAutoRestoresModifiedFile(t *testing.T) {
	dir, st, log := setup(t)

	confPath := filepath.Join(dir, "nginx.conf")
	if err := os.WriteFile(confPath, []byte("known-good"), 0o644); err != nil {
		t.Fatal(err)
	}

	manifestPath := filepath.Join(dir, "manifest.json")
	w := New(manifestPath, []string{confPath}, nil, st, log)

	// First pass establishes the known-good baseline and primes the store.
	if _, err := w.Check(); err != nil {
		t.Fatal(err)
	}
	baseline, err := manifest.New(manifestPath)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.Put([]byte("known-good")); err != nil {
		t.Fatal(err)
	}
	_ = baseline

	// Tamper with the file, then check again.
	if err := os.WriteFile(confPath, []byte("tampered"), 0o644); err != nil {
		t.Fatal(err)
	}

	res, err := w.Check()
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
}

func TestCheckFlagsConfirmFirstChanges(t *testing.T) {
	dir, st, log := setup(t)

	sudoersPath := filepath.Join(dir, "sudoers")
	if err := os.WriteFile(sudoersPath, []byte("root ALL=(ALL) ALL"), 0o644); err != nil {
		t.Fatal(err)
	}

	classify := func(path string) manifest.Class { return manifest.ConfirmFirst }
	manifestPath := filepath.Join(dir, "manifest.json")
	w := New(manifestPath, []string{sudoersPath}, classify, st, log)

	if _, err := w.Check(); err != nil {
		t.Fatal(err)
	}

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
}
