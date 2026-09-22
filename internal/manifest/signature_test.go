package manifest

import (
	"crypto/ed25519"
	"crypto/rand"
	"testing"
)

func TestSignatureBindsIdentityTierAndRecords(t *testing.T) {
	public, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	m := &Manifest{Generation: 1, Records: []Record{{Path: "/example", Hash: "known"}}}
	if err := m.Sign(key, "box1", "config"); err != nil {
		t.Fatal(err)
	}
	if err := m.Verify(public, "box1", "config"); err != nil {
		t.Fatal(err)
	}
	if err := m.Verify(public, "box2", "config"); err == nil {
		t.Fatal("accepted wrong source")
	}
	if err := m.Verify(public, "box1", "data"); err == nil {
		t.Fatal("accepted wrong tier")
	}
	m.Records[0].Hash = "altered"
	if err := m.Verify(public, "box1", "config"); err == nil {
		t.Fatal("accepted modified content")
	}
}
