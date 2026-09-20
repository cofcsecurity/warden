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

	w := New(manifestPath, []string{confPath}, nil, st, log)

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

	w := New(manifestPath, []string{confPath}, nil, st, log)
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

func TestCheckFlagsConfirmFirstChanges(t *testing.T) {
	dir, st, log := setup(t)

	sudoersPath := filepath.Join(dir, "sudoers")
	if err := os.WriteFile(sudoersPath, []byte("root ALL=(ALL) ALL"), 0o644); err != nil {
		t.Fatal(err)
	}

	classify := func(path string) manifest.Class { return manifest.ConfirmFirst }
	manifestPath := filepath.Join(dir, "manifest.json")
	snapshotBaseline(t, manifestPath, []string{sudoersPath}, classify, st)

	w := New(manifestPath, []string{sudoersPath}, classify, st, log)

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
