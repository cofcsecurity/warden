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

	has, err := target.HasManifest(1)
	if err != nil {
		t.Fatal(err)
	}
	if has {
		t.Fatalf("expected generation 1 to be absent")
	}

	if err := target.PutManifest(1, []byte(`{"generation":1}`)); err != nil {
		t.Fatal(err)
	}

	has, err = target.HasManifest(1)
	if err != nil {
		t.Fatal(err)
	}
	if !has {
		t.Fatalf("expected generation 1 to be present after PutManifest")
	}
}
