package replicate

import (
	"bytes"
	"encoding/json"
	"fmt"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"warden/internal/manifest"
	"warden/internal/store"
)

// fakeTarget is an in-memory Target for testing Push/Pull's own logic in
// isolation from any real transport.
type fakeTarget struct {
	objects          map[string][]byte
	manifests        map[string]map[int][]byte
	audit            map[string][]byte
	putCalls         int
	putManifestCalls int
	putAuditCalls    int
}

func newFakeTarget() *fakeTarget {
	return &fakeTarget{
		objects:   map[string][]byte{},
		manifests: map[string]map[int][]byte{},
		audit:     map[string][]byte{},
	}
}

func (f *fakeTarget) HasAudit(name string) (bool, error) {
	_, ok := f.audit[name]
	return ok, nil
}

func (f *fakeTarget) PutAudit(name string, data []byte) error {
	f.putAuditCalls++
	if _, ok := f.audit[name]; ok {
		return nil // additive-only, same as the real targets
	}
	f.audit[name] = data
	return nil
}

func (f *fakeTarget) GetAudit(name string) ([]byte, error) {
	data, ok := f.audit[name]
	if !ok {
		return nil, fmt.Errorf("fakeTarget: no audit segment %s", name)
	}
	return data, nil
}

func (f *fakeTarget) AuditSegments() ([]string, error) {
	var names []string
	for name := range f.audit {
		names = append(names, name)
	}
	sort.Strings(names)
	return names, nil
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

func (f *fakeTarget) Get(hash string) ([]byte, error) {
	content, ok := f.objects[hash]
	if !ok {
		return nil, fmt.Errorf("fakeTarget: no object %s", hash)
	}
	return content, nil
}

func (f *fakeTarget) HasManifest(namespace string, generation int) (bool, error) {
	_, ok := f.manifests[namespace][generation]
	return ok, nil
}

func (f *fakeTarget) PutManifest(namespace string, generation int, data []byte) error {
	f.putManifestCalls++
	if f.manifests[namespace] == nil {
		f.manifests[namespace] = map[int][]byte{}
	}
	if _, ok := f.manifests[namespace][generation]; ok {
		return nil
	}
	f.manifests[namespace][generation] = data
	return nil
}

func (f *fakeTarget) GetManifest(namespace string, generation int) ([]byte, error) {
	data, ok := f.manifests[namespace][generation]
	if !ok {
		return nil, fmt.Errorf("fakeTarget: no manifest %s generation %d", namespace, generation)
	}
	return data, nil
}

func (f *fakeTarget) ManifestGenerations(namespace string) ([]int, error) {
	var gens []int
	for g := range f.manifests[namespace] {
		gens = append(gens, g)
	}
	sort.Ints(gens) // match the real Target implementations' documented order
	return gens, nil
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

	if err := r.Push("config", m, manifestData, st); err != nil {
		t.Fatal(err)
	}

	if len(target.objects) != 1 {
		t.Fatalf("expected 1 object pushed, got %d", len(target.objects))
	}
	if string(target.objects[hash]) != "nginx.conf contents" {
		t.Errorf("pushed object content mismatch: got %q", target.objects[hash])
	}
	if len(target.manifests["config"]) != 1 || string(target.manifests["config"][1]) != string(manifestData) {
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
	target.manifests["config"] = map[int][]byte{1: []byte(`{"generation":1}`)}

	r := New(target)
	if err := r.Push("config", m, []byte(`{"generation":1}`), st); err != nil {
		t.Fatal(err)
	}

	if target.putCalls != 0 {
		t.Errorf("expected Put not to be called for an object the target already has, got %d calls", target.putCalls)
	}
	if target.putManifestCalls != 0 {
		t.Errorf("expected PutManifest not to be called for a generation the target already has, got %d calls", target.putManifestCalls)
	}
}

func TestPushKeepsTierNamespacesSeparate(t *testing.T) {
	dir := t.TempDir()
	st, err := store.New(filepath.Join(dir, "objects"))
	if err != nil {
		t.Fatal(err)
	}
	hash, err := st.Put([]byte("x"))
	if err != nil {
		t.Fatal(err)
	}

	m := &manifest.Manifest{Generation: 1, Records: []manifest.Record{{Path: "/etc/a", Hash: hash}}}
	target := newFakeTarget()
	r := New(target)

	if err := r.Push("config", m, []byte("config manifest"), st); err != nil {
		t.Fatal(err)
	}
	if err := r.Push("data", m, []byte("data manifest"), st); err != nil {
		t.Fatal(err)
	}

	if string(target.manifests["config"][1]) != "config manifest" {
		t.Errorf("config tier generation 1 got clobbered: %q", target.manifests["config"][1])
	}
	if string(target.manifests["data"][1]) != "data manifest" {
		t.Errorf("data tier generation 1 got clobbered: %q", target.manifests["data"][1])
	}
}

func TestRetrieverPullFetchesManifestAndObjects(t *testing.T) {
	dir := t.TempDir()
	st, err := store.New(filepath.Join(dir, "objects"))
	if err != nil {
		t.Fatal(err)
	}

	// The hash must be the real content-addressed hash of the object
	// (store.Put computes it from content, it never trusts a caller's
	// label), so compute it via a throwaway store the same way a real
	// source box would have when it originally snapshotted this file.
	content := []byte("known-good nginx.conf")
	sourceStore, err := store.New(filepath.Join(t.TempDir(), "objects"))
	if err != nil {
		t.Fatal(err)
	}
	hash, err := sourceStore.Put(content)
	if err != nil {
		t.Fatal(err)
	}

	target := newFakeTarget()
	target.objects[hash] = content
	target.manifests["config"] = map[int][]byte{
		1: mustMarshalManifest(t, &manifest.Manifest{
			Generation: 1,
			Records:    []manifest.Record{{Path: "/etc/nginx/nginx.conf", Hash: hash}},
		}),
	}

	r := NewRetriever(target)
	m, err := r.Pull("config", 1, st)
	if err != nil {
		t.Fatal(err)
	}
	if m.Generation != 1 || len(m.Records) != 1 {
		t.Fatalf("unexpected pulled manifest: %+v", m)
	}

	got, err := st.Get(hash)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, content) {
		t.Fatalf("pulled object content mismatch: got %q", got)
	}
}

func TestRetrieverLatestGeneration(t *testing.T) {
	target := newFakeTarget()
	target.manifests["config"] = map[int][]byte{1: []byte("a"), 3: []byte("b"), 2: []byte("c")}

	r := NewRetriever(target)
	latest, err := r.LatestGeneration("config")
	if err != nil {
		t.Fatal(err)
	}
	if latest != 3 {
		t.Fatalf("got %d, want 3", latest)
	}
}

func TestRetrieverLatestGenerationErrorsWhenNoneAvailable(t *testing.T) {
	r := NewRetriever(newFakeTarget())
	if _, err := r.LatestGeneration("config"); err == nil {
		t.Fatal("expected an error when no generations are available")
	}
}

func mustMarshalManifest(t *testing.T, m *manifest.Manifest) []byte {
	t.Helper()
	data, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func TestPushAuditIsAdditiveAndDeduplicates(t *testing.T) {
	target := newFakeTarget()
	r := New(target)

	name := AuditSegmentName("boxB", time.Unix(1700000000, 0), 0)
	if err := r.PushAudit(name, []byte(`{"action":"pass"}`+"\n")); err != nil {
		t.Fatal(err)
	}
	if err := r.PushAudit(name, []byte("different content entirely\n")); err != nil {
		t.Fatal(err)
	}

	if target.putAuditCalls != 1 {
		t.Errorf("expected the second push of the same segment name to be skipped, got %d puts", target.putAuditCalls)
	}
	if got := string(target.audit[name]); got != `{"action":"pass"}`+"\n" {
		t.Errorf("an existing segment must never be overwritten, got %q", got)
	}

	// Nothing to send is not an error, and writes nothing.
	if err := r.PushAudit(AuditSegmentName("boxB", time.Unix(1700000001, 0), 17), nil); err != nil {
		t.Fatal(err)
	}
	if target.putAuditCalls != 1 {
		t.Errorf("an empty segment must not be pushed, got %d puts", target.putAuditCalls)
	}
}

func TestPullAuditReassemblesInChronologicalOrder(t *testing.T) {
	target := newFakeTarget()
	r := New(target)

	at := time.Unix(1700000000, 0)
	if err := r.PushAudit(AuditSegmentName("boxB", at, 0), []byte("first\n")); err != nil {
		t.Fatal(err)
	}
	if err := r.PushAudit(AuditSegmentName("boxB", at.Add(time.Minute), 6), []byte("second\n")); err != nil {
		t.Fatal(err)
	}
	// A third segment written after a rotation restarts at offset 0, so
	// only the timestamp keeps it in order.
	if err := r.PushAudit(AuditSegmentName("boxB", at.Add(2*time.Minute), 0), []byte("third\n")); err != nil {
		t.Fatal(err)
	}

	got, err := NewRetriever(target).PullAudit()
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "first\nsecond\nthird\n" {
		t.Errorf("segments out of order: %q", got)
	}
}

func TestAuditSegmentNameIsFilesystemSafe(t *testing.T) {
	name := AuditSegmentName("box b/../..", time.Unix(1700000000, 0), 42)
	for _, bad := range []string{"/", "..", " "} {
		if strings.Contains(name, bad) {
			t.Errorf("segment name %q contains %q", name, bad)
		}
	}
}

func TestFSTargetRejectsAnAuditNameWithAPathSeparator(t *testing.T) {
	target, err := NewFSTarget(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := target.PutAudit("../escape.log", []byte("x")); err == nil {
		t.Error("expected a segment name with a path separator to be refused")
	}
}

func TestFSTargetAuditRoundTrip(t *testing.T) {
	root := t.TempDir()
	target, err := NewFSTarget(root)
	if err != nil {
		t.Fatal(err)
	}

	names, err := target.AuditSegments()
	if err != nil {
		t.Fatal(err)
	}
	if len(names) != 0 {
		t.Fatalf("expected no segments before anything is pushed, got %v", names)
	}

	name := AuditSegmentName("boxB", time.Unix(1700000000, 0), 0)
	if err := target.PutAudit(name, []byte("line\n")); err != nil {
		t.Fatal(err)
	}
	has, err := target.HasAudit(name)
	if err != nil {
		t.Fatal(err)
	}
	if !has {
		t.Error("expected the pushed segment to be present")
	}
	data, err := target.GetAudit(name)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "line\n" {
		t.Errorf("round trip mismatch: %q", data)
	}
}
