package manifest

import (
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
