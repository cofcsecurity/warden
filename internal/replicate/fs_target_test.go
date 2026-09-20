package replicate

import (
	"bytes"
	"os"
	"testing"
)

func TestFSTargetPutAndHas(t *testing.T) {
	target, err := NewFSTarget(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}

	has, err := target.Has("deadbeef")
	if err != nil {
		t.Fatal(err)
	}
	if has {
		t.Fatalf("expected object to be absent before Put")
	}

	if err := target.Put("deadbeef", []byte("content")); err != nil {
		t.Fatal(err)
	}

	has, err = target.Has("deadbeef")
	if err != nil {
		t.Fatal(err)
	}
	if !has {
		t.Fatalf("expected object to be present after Put")
	}

	got, err := target.Get("deadbeef")
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "content" {
		t.Fatalf("got %q, want %q", got, "content")
	}
}

func TestFSTargetPutIsAdditiveOnly(t *testing.T) {
	target, err := NewFSTarget(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}

	if err := target.Put("hash1", []byte("original")); err != nil {
		t.Fatal(err)
	}
	// A second Put under the same hash must not overwrite: content-addressed
	// storage means identical hashes should mean identical content anyway,
	// but the target must never assume that and clobber what's there.
	if err := target.Put("hash1", []byte("clobbered")); err != nil {
		t.Fatal(err)
	}

	got, err := os.ReadFile(target.objectPath("hash1"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, []byte("original")) {
		t.Fatalf("Put overwrote existing content: got %q", got)
	}
}

func TestFSTargetManifestRoundTrip(t *testing.T) {
	target, err := NewFSTarget(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}

	has, err := target.HasManifest("config", 1)
	if err != nil {
		t.Fatal(err)
	}
	if has {
		t.Fatalf("expected generation 1 to be absent")
	}

	if err := target.PutManifest("config", 1, []byte(`{"generation":1}`)); err != nil {
		t.Fatal(err)
	}

	has, err = target.HasManifest("config", 1)
	if err != nil {
		t.Fatal(err)
	}
	if !has {
		t.Fatalf("expected generation 1 to be present after PutManifest")
	}

	got, err := target.GetManifest("config", 1)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != `{"generation":1}` {
		t.Fatalf("got %q", got)
	}
}

func TestFSTargetManifestNamespacesDontCollide(t *testing.T) {
	target, err := NewFSTarget(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}

	if err := target.PutManifest("config", 1, []byte("config gen 1")); err != nil {
		t.Fatal(err)
	}
	if err := target.PutManifest("data", 1, []byte("data gen 1")); err != nil {
		t.Fatal(err)
	}

	gotConfig, err := target.GetManifest("config", 1)
	if err != nil {
		t.Fatal(err)
	}
	gotData, err := target.GetManifest("data", 1)
	if err != nil {
		t.Fatal(err)
	}
	if string(gotConfig) != "config gen 1" || string(gotData) != "data gen 1" {
		t.Fatalf("config and data tier generation 1 collided: config=%q data=%q", gotConfig, gotData)
	}
}

func TestFSTargetManifestGenerations(t *testing.T) {
	target, err := NewFSTarget(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}

	gens, err := target.ManifestGenerations("config")
	if err != nil {
		t.Fatal(err)
	}
	if len(gens) != 0 {
		t.Fatalf("expected no generations yet, got %v", gens)
	}

	for _, g := range []int{1, 3, 2} {
		if err := target.PutManifest("config", g, []byte("x")); err != nil {
			t.Fatal(err)
		}
	}

	gens, err = target.ManifestGenerations("config")
	if err != nil {
		t.Fatal(err)
	}
	if len(gens) != 3 || gens[0] != 1 || gens[1] != 2 || gens[2] != 3 {
		t.Fatalf("got %v, want [1 2 3] sorted", gens)
	}
}
