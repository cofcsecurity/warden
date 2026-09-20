package manifest

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestHashRoundTrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "a.conf")
	if err := os.WriteFile(path, []byte("hello"), 0o644); err != nil {
		t.Fatal(err)
	}

	m, err := Generate([]string{path}, nil, 1)
	if err != nil {
		t.Fatal(err)
	}
	if len(m.Records) != 1 {
		t.Fatalf("got %d records, want 1", len(m.Records))
	}

	manifestPath := filepath.Join(dir, "manifest.json")
	m.path = manifestPath
	if err := m.Save(); err != nil {
		t.Fatal(err)
	}

	loaded, err := New(manifestPath)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.Records[0].Hash != m.Records[0].Hash {
		t.Fatalf("hash mismatch after round trip: %s != %s", loaded.Records[0].Hash, m.Records[0].Hash)
	}
}

func TestGenerateSkipsMissingFiles(t *testing.T) {
	dir := t.TempDir()
	m, err := Generate([]string{filepath.Join(dir, "does-not-exist")}, nil, 1)
	if err != nil {
		t.Fatal(err)
	}
	if len(m.Records) != 0 {
		t.Fatalf("expected no records, got %d", len(m.Records))
	}
}

func TestDiffDetectsAddedRemovedModified(t *testing.T) {
	old := &Manifest{Records: []Record{
		{Path: "/etc/a", Hash: "aaa"},
		{Path: "/etc/b", Hash: "bbb"},
	}}
	new := &Manifest{Records: []Record{
		{Path: "/etc/a", Hash: "aaa"},          // unchanged
		{Path: "/etc/b", Hash: "bbb-modified"}, // modified
		{Path: "/etc/c", Hash: "ccc"},          // added
	}}

	changes := Diff(old, new)
	byPath := map[string]Change{}
	for _, c := range changes {
		byPath[c.Path] = c
	}

	if len(changes) != 2 {
		t.Fatalf("got %d changes, want 2: %+v", len(changes), changes)
	}
	if byPath["/etc/b"].Kind != Modified {
		t.Errorf("expected /etc/b to be Modified, got %s", byPath["/etc/b"].Kind)
	}
	if byPath["/etc/c"].Kind != Added {
		t.Errorf("expected /etc/c to be Added, got %s", byPath["/etc/c"].Kind)
	}

	removed := Diff(new, old)
	found := false
	for _, c := range removed {
		if c.Path == "/etc/c" && c.Kind == Removed {
			found = true
		}
	}
	if !found {
		t.Errorf("expected /etc/c to show as Removed when diffing backwards")
	}
}

func TestArchiveAndLoadGeneration(t *testing.T) {
	dir := t.TempDir()
	archiveDir := filepath.Join(dir, "manifests")

	path := filepath.Join(dir, "a.conf")
	if err := os.WriteFile(path, []byte("v1"), 0o644); err != nil {
		t.Fatal(err)
	}
	gen1, err := Generate([]string{path}, nil, 1)
	if err != nil {
		t.Fatal(err)
	}
	if err := gen1.Archive(archiveDir); err != nil {
		t.Fatal(err)
	}

	if err := os.WriteFile(path, []byte("v2-different-length"), 0o644); err != nil {
		t.Fatal(err)
	}
	gen2, err := Generate([]string{path}, nil, 2)
	if err != nil {
		t.Fatal(err)
	}
	if err := gen2.Archive(archiveDir); err != nil {
		t.Fatal(err)
	}

	loaded, err := LoadGeneration(archiveDir, 1)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.Records[0].Hash != gen1.Records[0].Hash {
		t.Fatalf("loaded generation 1 doesn't match: %s != %s", loaded.Records[0].Hash, gen1.Records[0].Hash)
	}

	gens, err := Generations(archiveDir)
	if err != nil {
		t.Fatal(err)
	}
	if len(gens) != 2 || gens[0] != 1 || gens[1] != 2 {
		t.Fatalf("got generations %v, want [1 2]", gens)
	}

	if _, err := LoadGeneration(archiveDir, 99); err == nil {
		t.Fatalf("expected error loading a generation that was never archived")
	}
}

func TestClassifyDefaultsToSafeAutoRestore(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "a.conf")
	if err := os.WriteFile(path, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}

	m, err := Generate([]string{path}, nil, 1)
	if err != nil {
		t.Fatal(err)
	}
	if m.Records[0].Class != SafeAutoRestore {
		t.Errorf("got class %s, want %s", m.Records[0].Class, SafeAutoRestore)
	}
}

func TestParseDecodesBytesWithNoBackingFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "a.conf")
	if err := os.WriteFile(path, []byte("hello"), 0o644); err != nil {
		t.Fatal(err)
	}

	original, err := Generate([]string{path}, nil, 7)
	if err != nil {
		t.Fatal(err)
	}
	data, err := json.MarshalIndent(original, "", "  ")
	if err != nil {
		t.Fatal(err)
	}

	parsed, err := Parse(data)
	if err != nil {
		t.Fatal(err)
	}
	if parsed.Generation != 7 || len(parsed.Records) != 1 || parsed.Records[0].Hash != original.Records[0].Hash {
		t.Fatalf("parsed manifest doesn't match original: %+v", parsed)
	}

	if err := parsed.Save(); err == nil {
		t.Fatal("expected Save to fail on a manifest with no backing path")
	}
}
