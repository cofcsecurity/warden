package store

import (
	"bytes"
	"os"
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

func TestGetRejectsCorruptionAndRecoversVerifiedContent(t *testing.T) {
	st, err := New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	content := []byte("approved")
	hash, err := st.Put(content)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(st.objectPath(hash), []byte("invalid gzip"), 0600); err != nil {
		t.Fatal(err)
	}
	if st.Has(hash) {
		t.Fatal("corrupt object considered available")
	}
	st.SetRecovery(func(string) ([]byte, error) { return content, nil })
	got, err := st.Get(hash)
	if err != nil || string(got) != string(content) {
		t.Fatalf("got=%q err=%v", got, err)
	}
	st.SetRecovery(nil)
	if _, err := st.Get(hash); err != nil {
		t.Fatalf("repair not cached: %v", err)
	}
	for _, hash := range []string{"", "a", "../../etc/passwd"} {
		if st.Has(hash) {
			t.Fatal("invalid hash exists")
		}
		if _, err := st.Get(hash); err == nil {
			t.Fatal("invalid hash accepted")
		}
	}
}
