package restore

import (
	"os"
	"path/filepath"
	"testing"

	"warden/internal/manifest"
	"warden/internal/store"
)

func TestPlanReportsDrift(t *testing.T) {
	dir := t.TempDir()
	confPath := filepath.Join(dir, "nginx.conf")
	if err := os.WriteFile(confPath, []byte("known-good"), 0o644); err != nil {
		t.Fatal(err)
	}

	snap, err := manifest.Generate([]string{confPath}, nil, 1)
	if err != nil {
		t.Fatal(err)
	}

	if err := os.WriteFile(confPath, []byte("tampered"), 0o644); err != nil {
		t.Fatal(err)
	}

	entries, err := Plan(snap, confPath)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || !entries[0].Changed {
		t.Fatalf("expected drift to be detected, got %+v", entries)
	}
}

func TestPlanUnknownTargetErrors(t *testing.T) {
	snap := &manifest.Manifest{Records: []manifest.Record{{Path: "/etc/known"}}}
	if _, err := Plan(snap, "/etc/unknown"); err == nil {
		t.Fatal("expected error for a target with no matching record")
	}
}

func TestApplyRestoresContentAndSkipsUnchanged(t *testing.T) {
	dir := t.TempDir()
	confPath := filepath.Join(dir, "app.conf")
	unrelatedPath := filepath.Join(dir, "unrelated.conf")

	if err := os.WriteFile(confPath, []byte("known-good"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(unrelatedPath, []byte("never touched"), 0o644); err != nil {
		t.Fatal(err)
	}

	st, err := store.New(filepath.Join(dir, "objects"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.Put([]byte("known-good")); err != nil {
		t.Fatal(err)
	}
	if _, err := st.Put([]byte("never touched")); err != nil {
		t.Fatal(err)
	}

	snap, err := manifest.Generate([]string{confPath, unrelatedPath}, nil, 1)
	if err != nil {
		t.Fatal(err)
	}

	if err := os.WriteFile(confPath, []byte("tampered"), 0o644); err != nil {
		t.Fatal(err)
	}

	entries, err := Plan(snap, "")
	if err != nil {
		t.Fatal(err)
	}

	// no service mapped for either path in this test
	r := New(st, func(string) (string, bool) { return "", false })
	results := r.Apply(entries)

	var restored, skipped int
	for _, res := range results {
		if res.Err != nil {
			t.Fatalf("unexpected error for %s: %v", res.Path, res.Err)
		}
		if res.Path == confPath {
			restored++
		}
		if res.Path == unrelatedPath {
			if !res.Skipped {
				t.Errorf("expected unrelated path to be skipped, got %+v", res)
			}
			skipped++
		}
	}
	if restored != 1 || skipped != 1 {
		t.Fatalf("expected 1 restored and 1 skipped, got restored=%d skipped=%d", restored, skipped)
	}

	got, err := os.ReadFile(confPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "known-good" {
		t.Fatalf("got content %q, want %q", got, "known-good")
	}

	unrelatedContent, err := os.ReadFile(unrelatedPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(unrelatedContent) != "never touched" {
		t.Fatalf("unrelated file was modified: %q", unrelatedContent)
	}
}

func TestApplyWithNoServiceMapWritesDirectly(t *testing.T) {
	dir := t.TempDir()
	confPath := filepath.Join(dir, "app.conf")
	if err := os.WriteFile(confPath, []byte("known-good"), 0o644); err != nil {
		t.Fatal(err)
	}

	st, err := store.New(filepath.Join(dir, "objects"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.Put([]byte("known-good")); err != nil {
		t.Fatal(err)
	}

	snap, err := manifest.Generate([]string{confPath}, nil, 1)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(confPath, []byte("tampered"), 0o644); err != nil {
		t.Fatal(err)
	}

	entries, err := Plan(snap, "")
	if err != nil {
		t.Fatal(err)
	}

	r := New(st, nil) // nil ServiceMap
	results := r.Apply(entries)
	if len(results) != 1 || results[0].Err != nil {
		t.Fatalf("unexpected results: %+v", results)
	}
	if results[0].ServiceStopped != "" || results[0].ServiceStarted != "" {
		t.Errorf("expected no service interaction, got %+v", results[0])
	}
}

func TestApplyRefusesToWriteThroughASymlink(t *testing.T) {
	dir := t.TempDir()
	st, err := store.New(dir)
	if err != nil {
		t.Fatal(err)
	}
	hash, err := st.Put([]byte("known-good"))
	if err != nil {
		t.Fatal(err)
	}

	victim := filepath.Join(dir, "shadow")
	if err := os.WriteFile(victim, []byte("do not touch"), 0o600); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(dir, "nginx.conf")
	if err := os.Symlink(victim, target); err != nil {
		t.Fatal(err)
	}

	r := New(st, nil)
	results := r.Apply([]PlanEntry{{Path: target, TargetHash: hash, TargetMode: 0o644, Changed: true}})
	if len(results) != 1 || results[0].Err == nil {
		t.Fatalf("expected a refusal for the symlinked path, got %+v", results)
	}

	got, err := os.ReadFile(victim)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "do not touch" {
		t.Errorf("the symlink target was written through: %q", got)
	}
}
