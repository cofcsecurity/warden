package store

import (
	"bytes"
	"testing"
)

func TestPutGetRoundTrip(t *testing.T) {
	s, err := New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}

	content := []byte("known-good nginx.conf contents")
	hash, err := s.Put(content)
	if err != nil {
		t.Fatal(err)
	}

	got, err := s.Get(hash)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, content) {
		t.Fatalf("got %q, want %q", got, content)
	}
}

func TestPutDedups(t *testing.T) {
	s, err := New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}

	content := []byte("same content twice")
	h1, err := s.Put(content)
	if err != nil {
		t.Fatal(err)
	}
	h2, err := s.Put(content)
	if err != nil {
		t.Fatal(err)
	}
	if h1 != h2 {
		t.Fatalf("expected identical hashes, got %s and %s", h1, h2)
	}
	if !s.Has(h1) {
		t.Fatalf("expected store to report object as present")
	}
}

func TestPrune(t *testing.T) {
	s, err := New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}

	keepHash, err := s.Put([]byte("keep me"))
	if err != nil {
		t.Fatal(err)
	}
	dropHash, err := s.Put([]byte("drop me"))
	if err != nil {
		t.Fatal(err)
	}

	if err := s.Prune(map[string]bool{keepHash: true}); err != nil {
		t.Fatal(err)
	}

	if !s.Has(keepHash) {
		t.Errorf("expected kept object to survive prune")
	}
	if s.Has(dropHash) {
		t.Errorf("expected unreferenced object to be pruned")
	}
}
