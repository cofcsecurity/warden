package replicate

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"warden/internal/manifest"
)

func TestReceiverConfinesWritesAndRejectsMutation(t *testing.T) {
	root := t.TempDir()
	r, err := NewReceiver(root, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	sum := sha256.Sum256([]byte("approved"))
	hash := hex.EncodeToString(sum[:])
	put := Request{Operation: "put", Kind: "object", ID: hash, Data: []byte("approved")}
	if res := r.Handle(put); res.Error != "" {
		t.Fatal(res.Error)
	}
	if res := r.Handle(put); res.Error != "" {
		t.Fatal("idempotent write:", res.Error)
	}
	for _, q := range []Request{
		{Operation: "delete", Kind: "object", ID: hash},
		{Operation: "put", Kind: "object", ID: hash, Data: []byte("changed")},
		{Operation: "get", Kind: "object", ID: "../../etc/shadow"},
		{Operation: "put", Kind: "audit", ID: "../escape", Data: []byte("bad")},
		{Operation: "put", Kind: "manifest", Tier: "../../outside", Generation: 1},
		{Operation: "put", Kind: "heartbeat", ID: ".."},
	} {
		if res := r.Handle(q); res.Error == "" {
			t.Fatalf("accepted invalid request %+v", q)
		}
	}
	got := r.Handle(Request{Operation: "get", Kind: "object", ID: hash})
	if string(got.Data) != "approved" {
		t.Fatalf("original changed: %+v", got)
	}
	outside := t.TempDir()
	if err := os.Symlink(outside, filepath.Join(root, "audit")); err != nil {
		t.Fatal(err)
	}
	if res := r.Handle(Request{Operation: "put", Kind: "audit", ID: "escape.log", Data: []byte("bad")}); res.Error == "" {
		t.Fatal("escaped through symlink")
	}
	if _, err := os.Stat(filepath.Join(outside, "escape.log")); !os.IsNotExist(err) {
		t.Fatal("outside destination changed")
	}
}
func TestReceiverRetainsLineageAndRefusesReplacement(t *testing.T) {
	r, err := NewReceiver(t.TempDir(), 0)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	for g := 1; g <= 2; g++ {
		data, _ := json.Marshal(&manifest.Manifest{Generation: g})
		if res := r.Handle(Request{Operation: "put", Kind: "manifest", Tier: "config", Generation: g, Data: data}); res.Error != "" {
			t.Fatal(res.Error)
		}
	}
	res := r.Handle(Request{Operation: "list", Kind: "manifest", Tier: "config"})
	if len(res.Names) != 2 {
		t.Fatalf("lost remote generation record: %+v", res)
	}
	data, _ := json.Marshal(&manifest.Manifest{Generation: 1, Records: []manifest.Record{{Path: "/different"}}})
	if res := r.Handle(Request{Operation: "put", Kind: "manifest", Tier: "config", Generation: 1, Data: data}); res.Error == "" {
		t.Fatal("replaced immutable generation")
	}
}

func TestReceiverQuotaRefusesRatherThanEvicts(t *testing.T) {
	r, err := NewReceiver(t.TempDir(), 64)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	first := []byte("a small good backup")
	if res := r.Handle(Request{Operation: "put", Kind: "object", ID: hashOf(first), Data: first}); res.Error != "" {
		t.Fatal(res.Error)
	}
	flood := make([]byte, 128)
	if res := r.Handle(Request{Operation: "put", Kind: "object", ID: hashOf(flood), Data: flood}); res.Error == "" {
		t.Fatal("accepted a put beyond the quota")
	}
	if res := r.Handle(Request{Operation: "get", Kind: "object", ID: hashOf(first)}); res.Error != "" || string(res.Data) != string(first) {
		t.Fatalf("the earlier copy must survive: %+v", res)
	}
}

func hashOf(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}
func TestReceiverServesOnlyOneStrictRequest(t *testing.T) {
	r, err := NewReceiver(t.TempDir(), 0)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	var out bytes.Buffer
	if err := r.Serve(bytes.NewBufferString(`{"Operation":"list","Kind":"audit","Shell":"rm"}`), &out); err == nil {
		t.Fatal("accepted unknown protocol field")
	}
	if err := r.Serve(bytes.NewBufferString(`{"Operation":"list","Kind":"audit"} {}`), &out); err == nil {
		t.Fatal("accepted multiple requests")
	}
}

func TestReceiverTargetOverPinnedSSH(t *testing.T) {
	receiver, err := NewReceiver(t.TempDir(), 0)
	if err != nil {
		t.Fatal(err)
	}
	defer receiver.Close()
	signer := generateSigner(t)
	srv := startTestSSHServer(t, signer.PublicKey(), receiver)
	sshTarget, err := DialSSH(srv.addr, "backup", signer, srv.hostSigner.PublicKey(), "/ignored")
	if err != nil {
		t.Fatal(err)
	}
	defer sshTarget.Close()
	target := &ReceiverTarget{Transport: sshTarget}
	sum := sha256.Sum256([]byte("ssh object"))
	hash := hex.EncodeToString(sum[:])
	if err := target.Put(hash, []byte("ssh object")); err != nil {
		t.Fatal(err)
	}
	if has, err := target.Has(hash); err != nil || !has {
		t.Fatalf("has=%t err=%v", has, err)
	}
	got, err := target.Get(hash)
	if err != nil || string(got) != "ssh object" {
		t.Fatalf("got=%q err=%v", got, err)
	}
	if err := target.PutManifest("data", 3, []byte(`{"generation":3,"records":[]}`)); err != nil {
		t.Fatal(err)
	}
	if generations, err := target.ManifestGenerations("data"); err != nil || len(generations) != 1 || generations[0] != 3 {
		t.Fatalf("generations=%v err=%v", generations, err)
	}
}
