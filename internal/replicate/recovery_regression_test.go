package replicate

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"warden/internal/manifest"
	"warden/internal/store"
)

func TestRemoteWriteQuotesPathsAndPreservesExistingContent(t *testing.T) {
	root := filepath.Join(t.TempDir(), "path with ' quotes $(false) and spaces")
	target := filepath.Join(root, "object")
	for _, content := range []string{"first", "second"} {
		cmd := exec.Command("sh", "-c", remoteWriteCommand(target))
		cmd.Stdin = strings.NewReader(content)
		if output, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("write: %v %s", err, output)
		}
	}
	content, err := os.ReadFile(target)
	if err != nil || string(content) != "first" {
		t.Fatalf("content=%q err=%v", content, err)
	}
	temps, err := filepath.Glob(target + ".tmp.*")
	if err != nil || len(temps) != 0 {
		t.Fatalf("temps=%v err=%v", temps, err)
	}
}

func TestRetrieverRejectsWrongObjectBytes(t *testing.T) {
	st, err := store.New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	hash := strings.Repeat("a", 64)
	target := newFakeTarget()
	m := &manifest.Manifest{Generation: 1, Records: []manifest.Record{{Path: "/test", Hash: hash}}}
	data, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	if err := target.PutManifest("config", 1, data); err != nil {
		t.Fatal(err)
	}
	target.objects[hash] = []byte("wrong data")
	if _, err := NewRetriever(target).Pull("config", 1, st); err == nil {
		t.Fatal("accepted object with a different hash")
	}
	if st.Has(hash) {
		t.Fatal("invalid object cached")
	}
	m.Records[0].Hash = "x"
	data, err = json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	target.manifests["config"][1] = data
	if _, err := NewRetriever(target).Pull("config", 1, st); err == nil {
		t.Fatal("accepted malformed hash")
	}
}
