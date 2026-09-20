package replicate

import (
	"path/filepath"
	"testing"

	"warden/internal/manifest"
	"warden/internal/store"
)

// fakeTarget is an in-memory Target for testing Push's own logic in
// isolation from any real transport.
type fakeTarget struct {
	objects          map[string][]byte
	manifests        map[int][]byte
	putCalls         int
	putManifestCalls int
}

func newFakeTarget() *fakeTarget {
	return &fakeTarget{objects: map[string][]byte{}, manifests: map[int][]byte{}}
}

func (f *fakeTarget) Has(hash string) (bool, error) {
	_, ok := f.objects[hash]
	return ok, nil
}

func (f *fakeTarget) Put(hash string, content []byte) error {
	f.putCalls++
	if _, ok := f.objects[hash]; ok {
		return nil // additive-only: real targets don't overwrite either
	}
	f.objects[hash] = content
	return nil
}

func (f *fakeTarget) HasManifest(generation int) (bool, error) {
	_, ok := f.manifests[generation]
	return ok, nil
}

func (f *fakeTarget) PutManifest(generation int, data []byte) error {
	f.putManifestCalls++
	if _, ok := f.manifests[generation]; ok {
		return nil
	}
	f.manifests[generation] = data
	return nil
}

func TestPushSendsNewObjectsAndManifest(t *testing.T) {
	dir := t.TempDir()
	st, err := store.New(filepath.Join(dir, "objects"))
	if err != nil {
		t.Fatal(err)
	}

	hash, err := st.Put([]byte("nginx.conf contents"))
	if err != nil {
		t.Fatal(err)
	}

	m := &manifest.Manifest{
		Generation: 1,
		Records:    []manifest.Record{{Path: "/etc/nginx/nginx.conf", Hash: hash}},
	}
	manifestData := []byte(`{"generation":1}`)

	target := newFakeTarget()
	r := New(target)

	if err := r.Push(m, manifestData, st); err != nil {
		t.Fatal(err)
	}

	if len(target.objects) != 1 {
		t.Fatalf("expected 1 object pushed, got %d", len(target.objects))
	}
	if string(target.objects[hash]) != "nginx.conf contents" {
		t.Errorf("pushed object content mismatch: got %q", target.objects[hash])
	}
	if len(target.manifests) != 1 || string(target.manifests[1]) != string(manifestData) {
		t.Errorf("expected manifest generation 1 to be pushed, got %+v", target.manifests)
	}
}

func TestPushSkipsObjectsAndManifestsAlreadyOnTarget(t *testing.T) {
	dir := t.TempDir()
	st, err := store.New(filepath.Join(dir, "objects"))
	if err != nil {
		t.Fatal(err)
	}
	hash, err := st.Put([]byte("already replicated"))
	if err != nil {
		t.Fatal(err)
	}

	m := &manifest.Manifest{
		Generation: 1,
		Records:    []manifest.Record{{Path: "/etc/a", Hash: hash}},
	}

	target := newFakeTarget()
	target.objects[hash] = []byte("already replicated")
	target.manifests[1] = []byte(`{"generation":1}`)

	r := New(target)
	if err := r.Push(m, []byte(`{"generation":1}`), st); err != nil {
		t.Fatal(err)
	}

	if target.putCalls != 0 {
		t.Errorf("expected Put not to be called for an object the target already has, got %d calls", target.putCalls)
	}
	if target.putManifestCalls != 0 {
		t.Errorf("expected PutManifest not to be called for a generation the target already has, got %d calls", target.putManifestCalls)
	}
}
